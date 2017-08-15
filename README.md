# bwapi-bot-loader

This requires building a special (32-bit) BWAPILauncher-4.1.2.
On ubuntu, you might need to apt install g++-multilib to be able to compile 32 bit programs.

## build bwloader.so
```
# git clone https://github.com/tscmoo/bwapi-bot-loader
# cd bwapi-bot-loader; mkdir build; cd build
# cmake -DCMAKE_BUILD_TYPE=Release ..
# make -j
```

## build BWAPILauncher-4.1.2 (don't do make install, since it might install 32 bit libraries which you don't want)
```
# git clone https://github.com/openbw/bwapi
# git clone https://github.com/openbw/openbw
# cd bwapi; mkdir build; cd build
# cmake -DCMAKE_BUILD_TYPE=Release -DOPENBW_DIR=../../openbw -DBUILD_COMPAT=1 ..
# make -j
```

## running
```
# BWAPI_CONFIG_AI__AI=./bwapi-bot-loader/build/bwloader.so:/path/to/bot.dll ./bwapi/build/bin/BWAPILauncher-4.1.2 
```
