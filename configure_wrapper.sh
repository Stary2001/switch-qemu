#!/usr/bin/env bash
source /opt/devkitpro/devkita64.sh
source /opt/devkitpro/switchvars.sh
export PATH=$PATH:/opt/devkitpro/devkitA64/bin
./configure --cross-prefix=aarch64-none-elf- --python=`which python2` --cpu=aarch64 --force-os=Horizon --extra-cflags="$CPPFLAGS $CFLAGS" --extra-ldflags="-specs=$DEVKITPRO/libnx/switch.specs $LDFLAGS" --with-coroutine=switch --disable-tools --target-list=i386-softmmu
