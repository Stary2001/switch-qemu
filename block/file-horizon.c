/*
 * Block driver for RAW files (posix)
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "trace.h"
#include "block/thread-pool.h"
#include "qemu/iov.h"
#include "block/raw-aio.h"
#include "qapi/qmp/qstring.h"

#include "scsi/pr-manager.h"
#include "scsi/constants.h"

#ifndef FS_NOCOW_FL
#define FS_NOCOW_FL                     0x00800000 /* Do not cow file */
#endif

//#define DEBUG_BLOCK

#ifdef DEBUG_BLOCK
# define DEBUG_BLOCK_PRINT 1
#else
# define DEBUG_BLOCK_PRINT 0
#endif
#define DPRINTF(fmt, ...) \
do { \
    if (DEBUG_BLOCK_PRINT) { \
        printf(fmt, ## __VA_ARGS__); \
    } \
} while (0)

/* OS X does not have O_DSYNC */
#ifndef O_DSYNC
#ifdef O_SYNC
#define O_DSYNC O_SYNC
#elif defined(O_FSYNC)
#define O_DSYNC O_FSYNC
#endif
#endif

/* Approximate O_DIRECT with O_DSYNC if O_DIRECT isn't available */
#ifndef O_DIRECT
#define O_DIRECT O_DSYNC
#endif

#define FTYPE_FILE   0
#define FTYPE_CD     1

#define MAX_BLOCKSIZE   4096

/* Posix file locking bytes. Libvirt takes byte 0, we start from higher bytes,
 * leaving a few more bytes for its future use. */
#define RAW_LOCK_PERM_BASE             100
#define RAW_LOCK_SHARED_BASE           200

typedef struct BDRVRawState {
    int fd;
    int lock_fd;
    bool use_lock;
    int type;
    int open_flags;
    size_t buf_align;

    /* The current permissions. */
    uint64_t perm;
    uint64_t shared_perm;

#ifdef CONFIG_XFS
    bool is_xfs:1;
#endif
    bool has_discard:1;
    bool has_write_zeroes:1;
    bool discard_zeroes:1;
    bool use_linux_aio:1;
    bool page_cache_inconsistent:1;
    bool has_fallocate;
    bool needs_alignment;

    PRManager *pr_mgr;
} BDRVRawState;

typedef struct BDRVRawReopenState {
    int fd;
    int open_flags;
} BDRVRawReopenState;

static int fd_open(BlockDriverState *bs);
static int64_t raw_getlength(BlockDriverState *bs);

typedef struct RawPosixAIOData {
    BlockDriverState *bs;
    int aio_fildes;
    union {
        struct iovec *aio_iov;
        void *aio_ioctl_buf;
    };
    int aio_niov;
    uint64_t aio_nbytes;
#define aio_ioctl_cmd   aio_nbytes /* for QEMU_AIO_IOCTL */
    off_t aio_offset;
    int aio_type;
} RawPosixAIOData;

static int raw_normalize_devicepath(const char **filename)
{
    return 0;
}

/*
 * Get logical block size via ioctl. On success store it in @sector_size_p.
 */
static int probe_logical_blocksize(int fd, unsigned int *sector_size_p)
{
    unsigned int sector_size;
    bool success = false;
    int i;

    errno = ENOTSUP;
    static const unsigned long ioctl_list[] = {
#ifdef BLKSSZGET
        BLKSSZGET,
#endif
#ifdef DKIOCGETBLOCKSIZE
        DKIOCGETBLOCKSIZE,
#endif
#ifdef DIOCGSECTORSIZE
        DIOCGSECTORSIZE,
#endif
    };

    /* Try a few ioctls to get the right size */
    for (i = 0; i < (int)ARRAY_SIZE(ioctl_list); i++) {
        if (ioctl(fd, ioctl_list[i], &sector_size) >= 0) {
            *sector_size_p = sector_size;
            success = true;
        }
    }

    return success ? 0 : -errno;
}

/**
 * Get physical block size of @fd.
 * On success, store it in @blk_size and return 0.
 * On failure, return -errno.
 */
static int probe_physical_blocksize(int fd, unsigned int *blk_size)
{
    return -ENOTSUP;
}

/* Check if read is allowed with given memory buffer and length.
 *
 * This function is used to check O_DIRECT memory buffer and request alignment.
 */
static bool raw_is_io_aligned(int fd, void *buf, size_t len)
{
    ssize_t ret = pread(fd, buf, len, 0);

    if (ret >= 0) {
        return true;
    }

    return false;
}

static int fd_open(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;

    /* this is just to ensure s->fd is sane (its called by io ops) */
    if (s->fd >= 0)
        return 0;
    return -EIO;
}

static void raw_probe_alignment(BlockDriverState *bs, int fd, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    char *buf;
    size_t max_align = MAX(MAX_BLOCKSIZE, getpagesize());

    /* For SCSI generic devices the alignment is not really used.
       With buffered I/O, we don't have any restrictions. */
    if (bdrv_is_sg(bs) || !s->needs_alignment) {
        bs->bl.request_alignment = 1;
        s->buf_align = 1;
        return;
    }

    bs->bl.request_alignment = 0;
    s->buf_align = 0;
    /* Let's try to use the logical blocksize for the alignment. */
    if (probe_logical_blocksize(fd, &bs->bl.request_alignment) < 0) {
        bs->bl.request_alignment = 0;
    }
#ifdef CONFIG_XFS
    if (s->is_xfs) {
        struct dioattr da;
        if (xfsctl(NULL, fd, XFS_IOC_DIOINFO, &da) >= 0) {
            bs->bl.request_alignment = da.d_miniosz;
            /* The kernel returns wrong information for d_mem */
            /* s->buf_align = da.d_mem; */
        }
    }
#endif

    /* If we could not get the sizes so far, we can only guess them */
    if (!s->buf_align) {
        size_t align;
        buf = qemu_memalign(max_align, 2 * max_align);
        for (align = 512; align <= max_align; align <<= 1) {
            if (raw_is_io_aligned(fd, buf + align, max_align)) {
                s->buf_align = align;
                break;
            }
        }
        qemu_vfree(buf);
    }

    if (!bs->bl.request_alignment) {
        size_t align;
        buf = qemu_memalign(s->buf_align, max_align);
        for (align = 512; align <= max_align; align <<= 1) {
            if (raw_is_io_aligned(fd, buf, align)) {
                bs->bl.request_alignment = align;
                break;
            }
        }
        qemu_vfree(buf);
    }

    if (!s->buf_align || !bs->bl.request_alignment) {
        error_setg(errp, "Could not find working O_DIRECT alignment");
        error_append_hint(errp, "Try cache.direct=off\n");
    }
}

static void raw_parse_flags(int bdrv_flags, int *open_flags)
{
    assert(open_flags != NULL);

    *open_flags |= O_BINARY;
    *open_flags &= ~O_ACCMODE;
    if (bdrv_flags & BDRV_O_RDWR) {
        *open_flags |= O_RDWR;
    } else {
        *open_flags |= O_RDONLY;
    }

    /* Use O_DSYNC for write-through caching, no flags for write-back caching,
     * and O_DIRECT for no caching. */
    if ((bdrv_flags & BDRV_O_NOCACHE)) {
        *open_flags |= O_DIRECT;
    }
}

static void raw_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
    bdrv_parse_filename_strip_prefix(filename, "file:", options);
}

static QemuOptsList raw_runtime_opts = {
    .name = "raw",
    .head = QTAILQ_HEAD_INITIALIZER(raw_runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "File name of the image",
        },
        {
            .name = "aio",
            .type = QEMU_OPT_STRING,
            .help = "host AIO implementation (threads, native)",
        },
        {
            .name = "locking",
            .type = QEMU_OPT_STRING,
            .help = "file locking mode (on/off/auto, default: auto)",
        },
        {
            .name = "pr-manager",
            .type = QEMU_OPT_STRING,
            .help = "id of persistent reservation manager object (default: none)",
        },
        { /* end of list */ }
    },
};

static int raw_open_common(BlockDriverState *bs, QDict *options,
                           int bdrv_flags, int open_flags, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    QemuOpts *opts;
    Error *local_err = NULL;
    const char *filename = NULL;
    const char *str;
    BlockdevAioOptions aio, aio_default;
    int fd, ret;
    struct stat st;
    OnOffAuto locking;

    opts = qemu_opts_create(&raw_runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }

    filename = qemu_opt_get(opts, "filename");

    ret = raw_normalize_devicepath(&filename);
    if (ret != 0) {
        error_setg_errno(errp, -ret, "Could not normalize device path");
        goto fail;
    }

    aio_default = (bdrv_flags & BDRV_O_NATIVE_AIO)
                  ? BLOCKDEV_AIO_OPTIONS_NATIVE
                  : BLOCKDEV_AIO_OPTIONS_THREADS;
    aio = qapi_enum_parse(&BlockdevAioOptions_lookup,
                          qemu_opt_get(opts, "aio"),
                          aio_default, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }
    s->use_linux_aio = (aio == BLOCKDEV_AIO_OPTIONS_NATIVE);

    locking = qapi_enum_parse(&OnOffAuto_lookup,
                              qemu_opt_get(opts, "locking"),
                              ON_OFF_AUTO_AUTO, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }
    switch (locking) {
    case ON_OFF_AUTO_ON:
        s->use_lock = true;
        if (!qemu_has_ofd_lock()) {
            fprintf(stderr,
                    "File lock requested but OFD locking syscall is "
                    "unavailable, falling back to POSIX file locks.\n"
                    "Due to the implementation, locks can be lost "
                    "unexpectedly.\n");
        }
        break;
    case ON_OFF_AUTO_OFF:
        s->use_lock = false;
        break;
    case ON_OFF_AUTO_AUTO:
        s->use_lock = qemu_has_ofd_lock();
        break;
    default:
        abort();
    }

    str = qemu_opt_get(opts, "pr-manager");
    if (str) {
        s->pr_mgr = pr_manager_lookup(str, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            ret = -EINVAL;
            goto fail;
        }
    }

    s->open_flags = open_flags;
    raw_parse_flags(bdrv_flags, &s->open_flags);

    s->fd = -1;
    fd = qemu_open(filename, s->open_flags, 0644);
    if (fd < 0) {
        ret = -errno;
        error_setg_errno(errp, errno, "Could not open '%s'", filename);
        if (ret == -EROFS) {
            ret = -EACCES;
        }
        goto fail;
    }
    s->fd = fd;

    s->lock_fd = -1;
    if (s->use_lock) {
        fd = qemu_open(filename, s->open_flags);
        if (fd < 0) {
            ret = -errno;
            error_setg_errno(errp, errno, "Could not open '%s' for locking",
                             filename);
            qemu_close(s->fd);
            goto fail;
        }
        s->lock_fd = fd;
    }
    s->perm = 0;
    s->shared_perm = BLK_PERM_ALL;

#ifdef CONFIG_LINUX_AIO
     /* Currently Linux does AIO only for files opened with O_DIRECT */
    if (s->use_linux_aio && !(s->open_flags & O_DIRECT)) {
        error_setg(errp, "aio=native was specified, but it requires "
                         "cache.direct=on, which was not specified.");
        ret = -EINVAL;
        goto fail;
    }
#else
    if (s->use_linux_aio) {
        error_setg(errp, "aio=native was specified, but is not supported "
                         "in this build.");
        ret = -EINVAL;
        goto fail;
    }
#endif /* !defined(CONFIG_LINUX_AIO) */

    s->has_discard = true;
    s->has_write_zeroes = true;
    bs->supported_zero_flags = BDRV_REQ_MAY_UNMAP;
    if ((bs->open_flags & BDRV_O_NOCACHE) != 0) {
        s->needs_alignment = true;
    }

    if (fstat(s->fd, &st) < 0) {
        ret = -errno;
        error_setg_errno(errp, errno, "Could not stat file");
        goto fail;
    }
    if (S_ISREG(st.st_mode)) {
        s->discard_zeroes = true;
        s->has_fallocate = false;
    }
    if (S_ISBLK(st.st_mode)) {
#ifdef BLKDISCARDZEROES
        unsigned int arg;
        if (ioctl(s->fd, BLKDISCARDZEROES, &arg) == 0 && arg) {
            s->discard_zeroes = true;
        }
#endif
#ifdef __linux__
        /* On Linux 3.10, BLKDISCARD leaves stale data in the page cache.  Do
         * not rely on the contents of discarded blocks unless using O_DIRECT.
         * Same for BLKZEROOUT.
         */
        if (!(bs->open_flags & BDRV_O_NOCACHE)) {
            s->discard_zeroes = false;
            s->has_write_zeroes = false;
        }
#endif
    }
#ifdef __FreeBSD__
    if (S_ISCHR(st.st_mode)) {
        /*
         * The file is a char device (disk), which on FreeBSD isn't behind
         * a pager, so force all requests to be aligned. This is needed
         * so QEMU makes sure all IO operations on the device are aligned
         * to sector size, or else FreeBSD will reject them with EINVAL.
         */
        s->needs_alignment = true;
    }
#endif

#ifdef CONFIG_XFS
    if (platform_test_xfs_fd(s->fd)) {
        s->is_xfs = true;
    }
#endif

    ret = 0;
fail:
    if (filename && (bdrv_flags & BDRV_O_TEMPORARY)) {
        unlink(filename);
    }
    qemu_opts_del(opts);
    return ret;
}

static int raw_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVRawState *s = bs->opaque;

    s->type = FTYPE_FILE;
    return raw_open_common(bs, options, flags, 0, errp);
}

typedef enum {
    RAW_PL_PREPARE,
    RAW_PL_COMMIT,
    RAW_PL_ABORT,
} RawPermLockOp;

#define PERM_FOREACH(i) \
    for ((i) = 0; (1ULL << (i)) <= BLK_PERM_ALL; i++)

/* Lock bytes indicated by @perm_lock_bits and @shared_perm_lock_bits in the
 * file; if @unlock == true, also unlock the unneeded bytes.
 * @shared_perm_lock_bits is the mask of all permissions that are NOT shared.
 */
static int raw_apply_lock_bytes(BDRVRawState *s,
                                uint64_t perm_lock_bits,
                                uint64_t shared_perm_lock_bits,
                                bool unlock, Error **errp)
{
    int ret;
    int i;

    PERM_FOREACH(i) {
        int off = RAW_LOCK_PERM_BASE + i;
        if (perm_lock_bits & (1ULL << i)) {
            ret = qemu_lock_fd(s->lock_fd, off, 1, false);
            if (ret) {
                error_setg(errp, "Failed to lock byte %d", off);
                return ret;
            }
        } else if (unlock) {
            ret = qemu_unlock_fd(s->lock_fd, off, 1);
            if (ret) {
                error_setg(errp, "Failed to unlock byte %d", off);
                return ret;
            }
        }
    }
    PERM_FOREACH(i) {
        int off = RAW_LOCK_SHARED_BASE + i;
        if (shared_perm_lock_bits & (1ULL << i)) {
            ret = qemu_lock_fd(s->lock_fd, off, 1, false);
            if (ret) {
                error_setg(errp, "Failed to lock byte %d", off);
                return ret;
            }
        } else if (unlock) {
            ret = qemu_unlock_fd(s->lock_fd, off, 1);
            if (ret) {
                error_setg(errp, "Failed to unlock byte %d", off);
                return ret;
            }
        }
    }
    return 0;
}

/* Check "unshared" bytes implied by @perm and ~@shared_perm in the file. */
static int raw_check_lock_bytes(BDRVRawState *s,
                                uint64_t perm, uint64_t shared_perm,
                                Error **errp)
{
    int ret;
    int i;

    PERM_FOREACH(i) {
        int off = RAW_LOCK_SHARED_BASE + i;
        uint64_t p = 1ULL << i;
        if (perm & p) {
            ret = qemu_lock_fd_test(s->lock_fd, off, 1, true);
            if (ret) {
                char *perm_name = bdrv_perm_names(p);
                error_setg(errp,
                           "Failed to get \"%s\" lock",
                           perm_name);
                g_free(perm_name);
                error_append_hint(errp,
                                  "Is another process using the image?\n");
                return ret;
            }
        }
    }
    PERM_FOREACH(i) {
        int off = RAW_LOCK_PERM_BASE + i;
        uint64_t p = 1ULL << i;
        if (!(shared_perm & p)) {
            ret = qemu_lock_fd_test(s->lock_fd, off, 1, true);
            if (ret) {
                char *perm_name = bdrv_perm_names(p);
                error_setg(errp,
                           "Failed to get shared \"%s\" lock",
                           perm_name);
                g_free(perm_name);
                error_append_hint(errp,
                                  "Is another process using the image?\n");
                return ret;
            }
        }
    }
    return 0;
}

static int raw_handle_perm_lock(BlockDriverState *bs,
                                RawPermLockOp op,
                                uint64_t new_perm, uint64_t new_shared,
                                Error **errp)
{
    BDRVRawState *s = bs->opaque;
    int ret = 0;
    Error *local_err = NULL;

    if (!s->use_lock) {
        return 0;
    }

    if (bdrv_get_flags(bs) & BDRV_O_INACTIVE) {
        return 0;
    }

    assert(s->lock_fd > 0);

    switch (op) {
    case RAW_PL_PREPARE:
        ret = raw_apply_lock_bytes(s, s->perm | new_perm,
                                   ~s->shared_perm | ~new_shared,
                                   false, errp);
        if (!ret) {
            ret = raw_check_lock_bytes(s, new_perm, new_shared, errp);
            if (!ret) {
                return 0;
            }
        }
        op = RAW_PL_ABORT;
        /* fall through to unlock bytes. */
    case RAW_PL_ABORT:
        raw_apply_lock_bytes(s, s->perm, ~s->shared_perm, true, &local_err);
        if (local_err) {
            /* Theoretically the above call only unlocks bytes and it cannot
             * fail. Something weird happened, report it.
             */
            error_report_err(local_err);
        }
        break;
    case RAW_PL_COMMIT:
        raw_apply_lock_bytes(s, new_perm, ~new_shared, true, &local_err);
        if (local_err) {
            /* Theoretically the above call only unlocks bytes and it cannot
             * fail. Something weird happened, report it.
             */
            error_report_err(local_err);
        }
        break;
    }
    return ret;
}

static int raw_reopen_prepare(BDRVReopenState *state,
                              BlockReopenQueue *queue, Error **errp)
{
    BDRVRawState *s;
    BDRVRawReopenState *rs;
    int ret = 0;
    Error *local_err = NULL;

    assert(state != NULL);
    assert(state->bs != NULL);

    s = state->bs->opaque;

    state->opaque = g_new0(BDRVRawReopenState, 1);
    rs = state->opaque;

    if (s->type == FTYPE_CD) {
        rs->open_flags |= O_NONBLOCK;
    }

    raw_parse_flags(state->flags, &rs->open_flags);

    rs->fd = -1;

    int fcntl_flags = O_APPEND | O_NONBLOCK;
#ifdef O_NOATIME
    fcntl_flags |= O_NOATIME;
#endif

#ifdef O_ASYNC
    /* Not all operating systems have O_ASYNC, and those that don't
     * will not let us track the state into rs->open_flags (typically
     * you achieve the same effect with an ioctl, for example I_SETSIG
     * on Solaris). But we do not use O_ASYNC, so that's fine.
     */
    assert((s->open_flags & O_ASYNC) == 0);
#endif

    if ((rs->open_flags & ~fcntl_flags) == (s->open_flags & ~fcntl_flags)) {
        /* dup the original fd */
        rs->fd = qemu_dup(s->fd);
        if (rs->fd >= 0) {
            ret = fcntl_setfl(rs->fd, rs->open_flags);
            if (ret) {
                qemu_close(rs->fd);
                rs->fd = -1;
            }
        }
    }

    /* If we cannot use fcntl, or fcntl failed, fall back to qemu_open() */
    if (rs->fd == -1) {
        const char *normalized_filename = state->bs->filename;
        ret = raw_normalize_devicepath(&normalized_filename);
        if (ret < 0) {
            error_setg_errno(errp, -ret, "Could not normalize device path");
        } else {
            assert(!(rs->open_flags & O_CREAT));
            rs->fd = qemu_open(normalized_filename, rs->open_flags);
            if (rs->fd == -1) {
                error_setg_errno(errp, errno, "Could not reopen file");
                ret = -1;
            }
        }
    }

    /* Fail already reopen_prepare() if we can't get a working O_DIRECT
     * alignment with the new fd. */
    if (rs->fd != -1) {
        
    }

    return ret;
}

static void raw_reopen_commit(BDRVReopenState *state)
{
    BDRVRawReopenState *rs = state->opaque;
    BDRVRawState *s = state->bs->opaque;

    s->open_flags = rs->open_flags;

    qemu_close(s->fd);
    s->fd = rs->fd;

    g_free(state->opaque);
    state->opaque = NULL;
}


static void raw_reopen_abort(BDRVReopenState *state)
{
    BDRVRawReopenState *rs = state->opaque;

     /* nothing to do if NULL, we didn't get far enough */
    if (rs == NULL) {
        return;
    }

    if (rs->fd >= 0) {
        qemu_close(rs->fd);
        rs->fd = -1;
    }
    g_free(state->opaque);
    state->opaque = NULL;
}

static int hdev_get_max_transfer_length(BlockDriverState *bs, int fd)
{
    return -ENOSYS;
}


static int hdev_get_max_segments(const struct stat *st)
{
    return -ENOTSUP;
}

static void raw_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    struct stat st;

    if (!fstat(s->fd, &st)) {
        if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
            int ret = hdev_get_max_transfer_length(bs, s->fd);
            if (ret > 0 && ret <= BDRV_REQUEST_MAX_BYTES) {
                bs->bl.max_transfer = pow2floor(ret);
            }
            ret = hdev_get_max_segments(&st);
            if (ret > 0) {
                bs->bl.max_transfer = MIN(bs->bl.max_transfer,
                                          ret * getpagesize());
            }
        }
    }

    raw_probe_alignment(bs, s->fd, errp);
    bs->bl.min_mem_alignment = s->buf_align;
    bs->bl.opt_mem_alignment = MAX(s->buf_align, getpagesize());
}

static int check_for_dasd(int fd)
{
    return -1;
}

static ssize_t handle_aiocb_ioctl(RawPosixAIOData *aiocb)
{
    int ret;

    ret = ioctl(aiocb->aio_fildes, aiocb->aio_ioctl_cmd, aiocb->aio_ioctl_buf);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

static ssize_t handle_aiocb_flush(RawPosixAIOData *aiocb)
{
    BDRVRawState *s = aiocb->bs->opaque;
    int ret;

    if (s->page_cache_inconsistent) {
        return -EIO;
    }

    ret = qemu_fdatasync(aiocb->aio_fildes);
    if (ret == -1) {
        /* There is no clear definition of the semantics of a failing fsync(),
         * so we may have to assume the worst. The sad truth is that this
         * assumption is correct for Linux. Some pages are now probably marked
         * clean in the page cache even though they are inconsistent with the
         * on-disk contents. The next fdatasync() call would succeed, but no
         * further writeback attempt will be made. We can't get back to a state
         * in which we know what is on disk (we would have to rewrite
         * everything that was touched since the last fdatasync() at least), so
         * make bdrv_flush() fail permanently. Given that the behaviour isn't
         * really defined, I have little hope that other OSes are doing better.
         *
         * Obviously, this doesn't affect O_DIRECT, which bypasses the page
         * cache. */
        if ((s->open_flags & O_DIRECT) == 0) {
            s->page_cache_inconsistent = true;
        }
        return -errno;
    }
    return 0;
}

/*
 * Read/writes the data to/from a given linear buffer.
 *
 * Returns the number of bytes handles or -errno in case of an error. Short
 * reads are only returned if the end of the file is reached.
 */
static ssize_t handle_aiocb_rw_linear(RawPosixAIOData *aiocb, char *buf)
{
    ssize_t offset = 0;
    ssize_t len;

    while (offset < aiocb->aio_nbytes) {
        if (aiocb->aio_type & QEMU_AIO_WRITE) {
            len = pwrite(aiocb->aio_fildes,
                         (const char *)buf + offset,
                         aiocb->aio_nbytes - offset,
                         aiocb->aio_offset + offset);
        } else {
            len = pread(aiocb->aio_fildes,
                        buf + offset,
                        aiocb->aio_nbytes - offset,
                        aiocb->aio_offset + offset);
        }
        if (len == -1 && errno == EINTR) {
            continue;
        } else if (len == -1 && errno == EINVAL &&
                   (aiocb->bs->open_flags & BDRV_O_NOCACHE) &&
                   !(aiocb->aio_type & QEMU_AIO_WRITE) &&
                   offset > 0) {
            /* O_DIRECT pread() may fail with EINVAL when offset is unaligned
             * after a short read.  Assume that O_DIRECT short reads only occur
             * at EOF.  Therefore this is a short read, not an I/O error.
             */
            break;
        } else if (len == -1) {
            offset = -errno;
            break;
        } else if (len == 0) {
            break;
        }
        offset += len;
    }

    return offset;
}

static ssize_t handle_aiocb_rw(RawPosixAIOData *aiocb)
{
    ssize_t nbytes;
    char *buf;

    if (!(aiocb->aio_type & QEMU_AIO_MISALIGNED)) {
        /*
         * If there is just a single buffer, and it is properly aligned
         * we can just use plain pread/pwrite without any problems.
         */
        if (aiocb->aio_niov == 1) {
             return handle_aiocb_rw_linear(aiocb, aiocb->aio_iov->iov_base);
        }
        /*
         * We have more than one iovec, and all are properly aligned.
         *
         * Try preadv/pwritev first and fall back to linearizing the
         * buffer if it's not supported.
         */

        /*
         * XXX(hch): short read/write.  no easy way to handle the reminder
         * using these interfaces.  For now retry using plain
         * pread/pwrite?
         */
    }

    /*
     * Ok, we have to do it the hard way, copy all segments into
     * a single aligned buffer.
     */
    buf = qemu_try_blockalign(aiocb->bs, aiocb->aio_nbytes);
    if (buf == NULL) {
        return -ENOMEM;
    }

    if (aiocb->aio_type & QEMU_AIO_WRITE) {
        char *p = buf;
        int i;

        for (i = 0; i < aiocb->aio_niov; ++i) {
            memcpy(p, aiocb->aio_iov[i].iov_base, aiocb->aio_iov[i].iov_len);
            p += aiocb->aio_iov[i].iov_len;
        }
        assert(p - buf == aiocb->aio_nbytes);
    }

    nbytes = handle_aiocb_rw_linear(aiocb, buf);
    if (!(aiocb->aio_type & QEMU_AIO_WRITE)) {
        char *p = buf;
        size_t count = aiocb->aio_nbytes, copy;
        int i;

        for (i = 0; i < aiocb->aio_niov && count; ++i) {
            copy = count;
            if (copy > aiocb->aio_iov[i].iov_len) {
                copy = aiocb->aio_iov[i].iov_len;
            }
            memcpy(aiocb->aio_iov[i].iov_base, p, copy);
            assert(count >= copy);
            p     += copy;
            count -= copy;
        }
        assert(count == 0);
    }
    qemu_vfree(buf);

    return nbytes;
}

#ifdef CONFIG_XFS
static int xfs_write_zeroes(BDRVRawState *s, int64_t offset, uint64_t bytes)
{
    struct xfs_flock64 fl;
    int err;

    memset(&fl, 0, sizeof(fl));
    fl.l_whence = SEEK_SET;
    fl.l_start = offset;
    fl.l_len = bytes;

    if (xfsctl(NULL, s->fd, XFS_IOC_ZERO_RANGE, &fl) < 0) {
        err = errno;
        DPRINTF("cannot write zero range (%s)\n", strerror(errno));
        return -err;
    }

    return 0;
}

static int xfs_discard(BDRVRawState *s, int64_t offset, uint64_t bytes)
{
    struct xfs_flock64 fl;
    int err;

    memset(&fl, 0, sizeof(fl));
    fl.l_whence = SEEK_SET;
    fl.l_start = offset;
    fl.l_len = bytes;

    if (xfsctl(NULL, s->fd, XFS_IOC_UNRESVSP64, &fl) < 0) {
        err = errno;
        DPRINTF("cannot punch hole (%s)\n", strerror(errno));
        return -err;
    }

    return 0;
}
#endif

static int translate_err(int err)
{
    if (err == -ENODEV || err == -ENOSYS || err == -EOPNOTSUPP ||
        err == -ENOTTY) {
        err = -ENOTSUP;
    }
    return err;
}

static ssize_t handle_aiocb_write_zeroes_block(RawPosixAIOData *aiocb)
{
    int ret = -ENOTSUP;
    BDRVRawState *s = aiocb->bs->opaque;

    if (!s->has_write_zeroes) {
        return -ENOTSUP;
    }

#ifdef BLKZEROOUT
    do {
        uint64_t range[2] = { aiocb->aio_offset, aiocb->aio_nbytes };
        if (ioctl(aiocb->aio_fildes, BLKZEROOUT, range) == 0) {
            return 0;
        }
    } while (errno == EINTR);

    ret = translate_err(-errno);
#endif

    if (ret == -ENOTSUP) {
        s->has_write_zeroes = false;
    }
    return ret;
}

static ssize_t handle_aiocb_write_zeroes(RawPosixAIOData *aiocb)
{
    if (aiocb->aio_type & QEMU_AIO_BLKDEV) {
        return handle_aiocb_write_zeroes_block(aiocb);
    }

    return -ENOTSUP;
}

static ssize_t handle_aiocb_discard(RawPosixAIOData *aiocb)
{
    int ret = -EOPNOTSUPP;
    BDRVRawState *s = aiocb->bs->opaque;

    if (!s->has_discard) {
        return -ENOTSUP;
    }

    if (aiocb->aio_type & QEMU_AIO_BLKDEV) {
#ifdef BLKDISCARD
        do {
            uint64_t range[2] = { aiocb->aio_offset, aiocb->aio_nbytes };
            if (ioctl(aiocb->aio_fildes, BLKDISCARD, range) == 0) {
                return 0;
            }
        } while (errno == EINTR);

        ret = -errno;
#endif
    } else {
#ifdef CONFIG_XFS
        if (s->is_xfs) {
            return xfs_discard(s, aiocb->aio_offset, aiocb->aio_nbytes);
        }
#endif

#ifdef CONFIG_FALLOCATE_PUNCH_HOLE
        ret = do_fallocate(s->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                           aiocb->aio_offset, aiocb->aio_nbytes);
#endif
    }

    ret = translate_err(ret);
    if (ret == -ENOTSUP) {
        s->has_discard = false;
    }
    return ret;
}

static int aio_worker(void *arg)
{
    RawPosixAIOData *aiocb = arg;
    ssize_t ret = 0;

    switch (aiocb->aio_type & QEMU_AIO_TYPE_MASK) {
    case QEMU_AIO_READ:
        ret = handle_aiocb_rw(aiocb);
        if (ret >= 0 && ret < aiocb->aio_nbytes) {
            iov_memset(aiocb->aio_iov, aiocb->aio_niov, ret,
                      0, aiocb->aio_nbytes - ret);

            ret = aiocb->aio_nbytes;
        }
        if (ret == aiocb->aio_nbytes) {
            ret = 0;
        } else if (ret >= 0 && ret < aiocb->aio_nbytes) {
            ret = -EINVAL;
        }
        break;
    case QEMU_AIO_WRITE:
        ret = handle_aiocb_rw(aiocb);
        if (ret == aiocb->aio_nbytes) {
            ret = 0;
        } else if (ret >= 0 && ret < aiocb->aio_nbytes) {
            ret = -EINVAL;
        }
        break;
    case QEMU_AIO_FLUSH:
        ret = handle_aiocb_flush(aiocb);
        break;
    case QEMU_AIO_IOCTL:
        ret = handle_aiocb_ioctl(aiocb);
        break;
    case QEMU_AIO_DISCARD:
        ret = handle_aiocb_discard(aiocb);
        break;
    case QEMU_AIO_WRITE_ZEROES:
        ret = handle_aiocb_write_zeroes(aiocb);
        break;
    default:
        fprintf(stderr, "invalid aio request (0x%x)\n", aiocb->aio_type);
        ret = -EINVAL;
        break;
    }

    g_free(aiocb);
    return ret;
}

static int paio_submit_co(BlockDriverState *bs, int fd,
                          int64_t offset, QEMUIOVector *qiov,
                          int bytes, int type)
{
    RawPosixAIOData *acb = g_new(RawPosixAIOData, 1);
    ThreadPool *pool;

    acb->bs = bs;
    acb->aio_type = type;
    acb->aio_fildes = fd;

    acb->aio_nbytes = bytes;
    acb->aio_offset = offset;

    if (qiov) {
        acb->aio_iov = qiov->iov;
        acb->aio_niov = qiov->niov;
        assert(qiov->size == bytes);
    }

    trace_paio_submit_co(offset, bytes, type);
    pool = aio_get_thread_pool(bdrv_get_aio_context(bs));
    return thread_pool_submit_co(pool, aio_worker, acb);
}

static BlockAIOCB *paio_submit(BlockDriverState *bs, int fd,
        int64_t offset, QEMUIOVector *qiov, int bytes,
        BlockCompletionFunc *cb, void *opaque, int type)
{
    RawPosixAIOData *acb = g_new(RawPosixAIOData, 1);
    ThreadPool *pool;

    acb->bs = bs;
    acb->aio_type = type;
    acb->aio_fildes = fd;

    acb->aio_nbytes = bytes;
    acb->aio_offset = offset;

    if (qiov) {
        acb->aio_iov = qiov->iov;
        acb->aio_niov = qiov->niov;
        assert(qiov->size == acb->aio_nbytes);
    }

    trace_paio_submit(acb, opaque, offset, bytes, type);
    pool = aio_get_thread_pool(bdrv_get_aio_context(bs));
    return thread_pool_submit_aio(pool, aio_worker, acb, cb, opaque);
}

static int coroutine_fn raw_co_prw(BlockDriverState *bs, uint64_t offset,
                                   uint64_t bytes, QEMUIOVector *qiov, int type)
{
    BDRVRawState *s = bs->opaque;

    if (fd_open(bs) < 0)
        return -EIO;

    /*
     * Check if the underlying device requires requests to be aligned,
     * and if the request we are trying to submit is aligned or not.
     * If this is the case tell the low-level driver that it needs
     * to copy the buffer.
     */
    if (s->needs_alignment) {
        if (!bdrv_qiov_is_aligned(bs, qiov)) {
            type |= QEMU_AIO_MISALIGNED;
#ifdef CONFIG_LINUX_AIO
        } else if (s->use_linux_aio) {
            LinuxAioState *aio = aio_get_linux_aio(bdrv_get_aio_context(bs));
            assert(qiov->size == bytes);
            return laio_co_submit(bs, aio, s->fd, offset, qiov, type);
#endif
        }
    }

    return paio_submit_co(bs, s->fd, offset, qiov, bytes, type);
}

static int coroutine_fn raw_co_preadv(BlockDriverState *bs, uint64_t offset,
                                      uint64_t bytes, QEMUIOVector *qiov,
                                      int flags)
{
    return raw_co_prw(bs, offset, bytes, qiov, QEMU_AIO_READ);
}

static int coroutine_fn raw_co_pwritev(BlockDriverState *bs, uint64_t offset,
                                       uint64_t bytes, QEMUIOVector *qiov,
                                       int flags)
{
    assert(flags == 0);
    return raw_co_prw(bs, offset, bytes, qiov, QEMU_AIO_WRITE);
}

static void raw_aio_plug(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;
    if (s->use_linux_aio) {
        LinuxAioState *aio = aio_get_linux_aio(bdrv_get_aio_context(bs));
        laio_io_plug(bs, aio);
    }
#endif
}

static void raw_aio_unplug(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;
    if (s->use_linux_aio) {
        LinuxAioState *aio = aio_get_linux_aio(bdrv_get_aio_context(bs));
        laio_io_unplug(bs, aio);
    }
#endif
}

static BlockAIOCB *raw_aio_flush(BlockDriverState *bs,
        BlockCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;

    if (fd_open(bs) < 0)
        return NULL;

    return paio_submit(bs, s->fd, 0, NULL, 0, cb, opaque, QEMU_AIO_FLUSH);
}

static void raw_close(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;

    if (s->fd >= 0) {
        qemu_close(s->fd);
        s->fd = -1;
    }
    if (s->lock_fd >= 0) {
        qemu_close(s->lock_fd);
        s->lock_fd = -1;
    }
}

/**
 * Truncates the given regular file @fd to @offset and, when growing, fills the
 * new space according to @prealloc.
 *
 * Returns: 0 on success, -errno on failure.
 */
static int raw_regular_truncate(int fd, int64_t offset, PreallocMode prealloc,
                                Error **errp)
{
    int result = 0;
    int64_t current_length = 0;
    char *buf = NULL;
    struct stat st;

    if (fstat(fd, &st) < 0) {
        result = -errno;
        error_setg_errno(errp, -result, "Could not stat file");
        return result;
    }

    current_length = st.st_size;
    if (current_length > offset && prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Cannot use preallocation for shrinking files");
        return -ENOTSUP;
    }

    switch (prealloc) {
    case PREALLOC_MODE_FULL:
    {
        int64_t num = 0, left = offset - current_length;

        /*
         * Knowing the final size from the beginning could allow the file
         * system driver to do less allocations and possibly avoid
         * fragmentation of the file.
         */
        if (ftruncate(fd, offset) != 0) {
            result = -errno;
            error_setg_errno(errp, -result, "Could not resize file");
            goto out;
        }

        buf = g_malloc0(65536);

        result = lseek(fd, current_length, SEEK_SET);
        if (result < 0) {
            result = -errno;
            error_setg_errno(errp, -result,
                             "Failed to seek to the old end of file");
            goto out;
        }

        while (left > 0) {
            num = MIN(left, 65536);
            result = write(fd, buf, num);
            if (result < 0) {
                result = -errno;
                error_setg_errno(errp, -result,
                                 "Could not write zeros for preallocation");
                goto out;
            }
            left -= result;
        }
        if (result >= 0) {
            result = fsync(fd);
            if (result < 0) {
                result = -errno;
                error_setg_errno(errp, -result,
                                 "Could not flush file to disk");
                goto out;
            }
        }
        goto out;
    }
    case PREALLOC_MODE_OFF:
        if (ftruncate(fd, offset) != 0) {
            result = -errno;
            error_setg_errno(errp, -result, "Could not resize file");
        }
        return result;
    default:
        result = -ENOTSUP;
        error_setg(errp, "Unsupported preallocation mode: %s",
                   PreallocMode_str(prealloc));
        return result;
    }

out:
    if (result < 0) {
        if (ftruncate(fd, current_length) < 0) {
            error_report("Failed to restore old file length: %s",
                         strerror(errno));
        }
    }

    g_free(buf);
    return result;
}

static int raw_truncate(BlockDriverState *bs, int64_t offset,
                        PreallocMode prealloc, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    struct stat st;
    int ret;

    if (fstat(s->fd, &st)) {
        ret = -errno;
        error_setg_errno(errp, -ret, "Failed to fstat() the file");
        return ret;
    }

    if (S_ISREG(st.st_mode)) {
        return raw_regular_truncate(s->fd, offset, prealloc, errp);
    }

    if (prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Preallocation mode '%s' unsupported for this "
                   "non-regular file", PreallocMode_str(prealloc));
        return -ENOTSUP;
    }

    if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
        if (offset > raw_getlength(bs)) {
            error_setg(errp, "Cannot grow device files");
            return -EINVAL;
        }
    } else {
        error_setg(errp, "Resizing this file is not supported");
        return -ENOTSUP;
    }

    return 0;
}

static int64_t raw_getlength(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    int ret;
    int64_t size;

    ret = fd_open(bs);
    if (ret < 0) {
        return ret;
    }

    size = lseek(s->fd, 0, SEEK_END);
    if (size < 0) {
        return -errno;
    }
    return size;
}

static int64_t raw_get_allocated_file_size(BlockDriverState *bs)
{
    struct stat st;
    BDRVRawState *s = bs->opaque;

    if (fstat(s->fd, &st) < 0) {
        return -errno;
    }
    return (int64_t)st.st_blocks * 512;
}

static int raw_create(const char *filename, QemuOpts *opts, Error **errp)
{
    int fd;
    int result = 0;
    int64_t total_size = 0;
    bool nocow = false;
    PreallocMode prealloc;
    char *buf = NULL;
    Error *local_err = NULL;

    strstart(filename, "file:", &filename);

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);
    nocow = qemu_opt_get_bool(opts, BLOCK_OPT_NOCOW, false);
    buf = qemu_opt_get_del(opts, BLOCK_OPT_PREALLOC);
    prealloc = qapi_enum_parse(&PreallocMode_lookup, buf,
                               PREALLOC_MODE_OFF, &local_err);
    g_free(buf);
    if (local_err) {
        error_propagate(errp, local_err);
        result = -EINVAL;
        goto out;
    }

    fd = qemu_open(filename, O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                   0644);
    if (fd < 0) {
        result = -errno;
        error_setg_errno(errp, -result, "Could not create file");
        goto out;
    }

    if (nocow) {
#ifdef __linux__
        /* Set NOCOW flag to solve performance issue on fs like btrfs.
         * This is an optimisation. The FS_IOC_SETFLAGS ioctl return value
         * will be ignored since any failure of this operation should not
         * block the left work.
         */
        int attr;
        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) == 0) {
            attr |= FS_NOCOW_FL;
            ioctl(fd, FS_IOC_SETFLAGS, &attr);
        }
#endif
    }

    result = raw_regular_truncate(fd, total_size, prealloc, errp);
    if (result < 0) {
        goto out_close;
    }

out_close:
    if (qemu_close(fd) != 0 && result == 0) {
        result = -errno;
        error_setg_errno(errp, -result, "Could not close the new file");
    }
out:
    return result;
}

/*
 * Find allocation range in @bs around offset @start.
 * May change underlying file descriptor's file offset.
 * If @start is not in a hole, store @start in @data, and the
 * beginning of the next hole in @hole, and return 0.
 * If @start is in a non-trailing hole, store @start in @hole and the
 * beginning of the next non-hole in @data, and return 0.
 * If @start is in a trailing hole or beyond EOF, return -ENXIO.
 * If we can't find out, return a negative errno other than -ENXIO.
 */
static int find_allocation(BlockDriverState *bs, off_t start,
                           off_t *data, off_t *hole)
{
#if defined SEEK_HOLE && defined SEEK_DATA
    BDRVRawState *s = bs->opaque;
    off_t offs;

    /*
     * SEEK_DATA cases:
     * D1. offs == start: start is in data
     * D2. offs > start: start is in a hole, next data at offs
     * D3. offs < 0, errno = ENXIO: either start is in a trailing hole
     *                              or start is beyond EOF
     *     If the latter happens, the file has been truncated behind
     *     our back since we opened it.  All bets are off then.
     *     Treating like a trailing hole is simplest.
     * D4. offs < 0, errno != ENXIO: we learned nothing
     */
    offs = lseek(s->fd, start, SEEK_DATA);
    if (offs < 0) {
        return -errno;          /* D3 or D4 */
    }
    assert(offs >= start);

    if (offs > start) {
        /* D2: in hole, next data at offs */
        *hole = start;
        *data = offs;
        return 0;
    }

    /* D1: in data, end not yet known */

    /*
     * SEEK_HOLE cases:
     * H1. offs == start: start is in a hole
     *     If this happens here, a hole has been dug behind our back
     *     since the previous lseek().
     * H2. offs > start: either start is in data, next hole at offs,
     *                   or start is in trailing hole, EOF at offs
     *     Linux treats trailing holes like any other hole: offs ==
     *     start.  Solaris seeks to EOF instead: offs > start (blech).
     *     If that happens here, a hole has been dug behind our back
     *     since the previous lseek().
     * H3. offs < 0, errno = ENXIO: start is beyond EOF
     *     If this happens, the file has been truncated behind our
     *     back since we opened it.  Treat it like a trailing hole.
     * H4. offs < 0, errno != ENXIO: we learned nothing
     *     Pretend we know nothing at all, i.e. "forget" about D1.
     */
    offs = lseek(s->fd, start, SEEK_HOLE);
    if (offs < 0) {
        return -errno;          /* D1 and (H3 or H4) */
    }
    assert(offs >= start);

    if (offs > start) {
        /*
         * D1 and H2: either in data, next hole at offs, or it was in
         * data but is now in a trailing hole.  In the latter case,
         * all bets are off.  Treating it as if it there was data all
         * the way to EOF is safe, so simply do that.
         */
        *data = start;
        *hole = offs;
        return 0;
    }

    /* D1 and H1 */
    return -EBUSY;
#else
    return -ENOTSUP;
#endif
}

/*
 * Returns the allocation status of the specified sectors.
 *
 * If 'sector_num' is beyond the end of the disk image the return value is 0
 * and 'pnum' is set to 0.
 *
 * 'pnum' is set to the number of sectors (including and immediately following
 * the specified sector) that are known to be in the same
 * allocated/unallocated state.
 *
 * 'nb_sectors' is the max value 'pnum' should be set to.  If nb_sectors goes
 * beyond the end of the disk image it will be clamped.
 */
static int64_t coroutine_fn raw_co_get_block_status(BlockDriverState *bs,
                                                    int64_t sector_num,
                                                    int nb_sectors, int *pnum,
                                                    BlockDriverState **file)
{
    off_t start, data = 0, hole = 0;
    int64_t total_size;
    int ret;

    ret = fd_open(bs);
    if (ret < 0) {
        return ret;
    }

    start = sector_num * BDRV_SECTOR_SIZE;
    total_size = bdrv_getlength(bs);
    if (total_size < 0) {
        return total_size;
    } else if (start >= total_size) {
        *pnum = 0;
        return 0;
    } else if (start + nb_sectors * BDRV_SECTOR_SIZE > total_size) {
        nb_sectors = DIV_ROUND_UP(total_size - start, BDRV_SECTOR_SIZE);
    }

    ret = find_allocation(bs, start, &data, &hole);
    if (ret == -ENXIO) {
        /* Trailing hole */
        *pnum = nb_sectors;
        ret = BDRV_BLOCK_ZERO;
    } else if (ret < 0) {
        /* No info available, so pretend there are no holes */
        *pnum = nb_sectors;
        ret = BDRV_BLOCK_DATA;
    } else if (data == start) {
        /* On a data extent, compute sectors to the end of the extent,
         * possibly including a partial sector at EOF. */
        *pnum = MIN(nb_sectors, DIV_ROUND_UP(hole - start, BDRV_SECTOR_SIZE));
        ret = BDRV_BLOCK_DATA;
    } else {
        /* On a hole, compute sectors to the beginning of the next extent.  */
        assert(hole == start);
        *pnum = MIN(nb_sectors, (data - start) / BDRV_SECTOR_SIZE);
        ret = BDRV_BLOCK_ZERO;
    }
    *file = bs;
    return ret | BDRV_BLOCK_OFFSET_VALID | start;
}

static coroutine_fn BlockAIOCB *raw_aio_pdiscard(BlockDriverState *bs,
    int64_t offset, int bytes,
    BlockCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;

    return paio_submit(bs, s->fd, offset, NULL, bytes,
                       cb, opaque, QEMU_AIO_DISCARD);
}

static int coroutine_fn raw_co_pwrite_zeroes(
    BlockDriverState *bs, int64_t offset,
    int bytes, BdrvRequestFlags flags)
{
    BDRVRawState *s = bs->opaque;

    if (!(flags & BDRV_REQ_MAY_UNMAP)) {
        return paio_submit_co(bs, s->fd, offset, NULL, bytes,
                              QEMU_AIO_WRITE_ZEROES);
    } else if (s->discard_zeroes) {
        return paio_submit_co(bs, s->fd, offset, NULL, bytes,
                              QEMU_AIO_DISCARD);
    }
    return -ENOTSUP;
}

static int raw_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVRawState *s = bs->opaque;

    bdi->unallocated_blocks_are_zero = s->discard_zeroes;
    bdi->can_write_zeroes_with_unmap = s->discard_zeroes;
    return 0;
}

static QemuOptsList raw_create_opts = {
    .name = "raw-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(raw_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        {
            .name = BLOCK_OPT_NOCOW,
            .type = QEMU_OPT_BOOL,
            .help = "Turn off copy-on-write (valid only on btrfs)"
        },
        {
            .name = BLOCK_OPT_PREALLOC,
            .type = QEMU_OPT_STRING,
            .help = "Preallocation mode (allowed values: off, falloc, full)"
        },
        { /* end of list */ }
    }
};

static int raw_check_perm(BlockDriverState *bs, uint64_t perm, uint64_t shared,
                          Error **errp)
{
    return raw_handle_perm_lock(bs, RAW_PL_PREPARE, perm, shared, errp);
}

static void raw_set_perm(BlockDriverState *bs, uint64_t perm, uint64_t shared)
{
    BDRVRawState *s = bs->opaque;
    raw_handle_perm_lock(bs, RAW_PL_COMMIT, perm, shared, NULL);
    s->perm = perm;
    s->shared_perm = shared;
}

static void raw_abort_perm_update(BlockDriverState *bs)
{
    raw_handle_perm_lock(bs, RAW_PL_ABORT, 0, 0, NULL);
}

BlockDriver bdrv_file = {
    .format_name = "file",
    .protocol_name = "file",
    .instance_size = sizeof(BDRVRawState),
    .bdrv_needs_filename = true,
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_parse_filename = raw_parse_filename,
    .bdrv_file_open = raw_open,
    .bdrv_reopen_prepare = raw_reopen_prepare,
    .bdrv_reopen_commit = raw_reopen_commit,
    .bdrv_reopen_abort = raw_reopen_abort,
    .bdrv_close = raw_close,
    .bdrv_create = raw_create,
    .bdrv_has_zero_init = bdrv_has_zero_init_1,
    .bdrv_co_get_block_status = raw_co_get_block_status,
    .bdrv_co_pwrite_zeroes = raw_co_pwrite_zeroes,

    .bdrv_co_preadv         = raw_co_preadv,
    .bdrv_co_pwritev        = raw_co_pwritev,
    .bdrv_aio_flush = raw_aio_flush,
    .bdrv_aio_pdiscard = raw_aio_pdiscard,
    .bdrv_refresh_limits = raw_refresh_limits,
    .bdrv_io_plug = raw_aio_plug,
    .bdrv_io_unplug = raw_aio_unplug,

    .bdrv_truncate = raw_truncate,
    .bdrv_getlength = raw_getlength,
    .bdrv_get_info = raw_get_info,
    .bdrv_get_allocated_file_size
                        = raw_get_allocated_file_size,
    .bdrv_check_perm = raw_check_perm,
    .bdrv_set_perm   = raw_set_perm,
    .bdrv_abort_perm_update = raw_abort_perm_update,
    .create_opts = &raw_create_opts,
};

static void bdrv_file_init(void)
{
    /*
     * Register all the drivers.  Note that order is important, the driver
     * registered last will get probed first.
     */
    bdrv_register(&bdrv_file);
}

block_init(bdrv_file_init);


ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    lseek(fd, offset, SEEK_SET);
    return read(fd, buf, count);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    lseek(fd, offset, SEEK_SET);
    return write(fd, buf, count);
}