#!/usr/bin/env bash
source /opt/devkitpro/devkita64.sh
source /opt/devkitpro/switchvars.sh
export PATH=$PATH:/opt/devkitpro/devkitA64/bin
export CFLAGS="-Og -ffunction-sections -fdata-sections -march=armv8-a -mtune=cortex-a57 -mtp=soft -fPIC -ftls-model=local-exec"

./configure --cross-prefix=aarch64-none-elf- --python=`which python2` --cpu=aarch64 --force-os=Horizon --extra-cflags="$CPPFLAGS $CFLAGS" --extra-ldflags="-specs=$DEVKITPRO/libnx/switch.specs $LDFLAGS" --with-coroutine=switch --disable-tools --enable-sdl --with-sdlabi=2.0 --target-list=i386-softmmu --enable-debug-info --enable-tcg-interpreter
