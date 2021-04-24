Mbed TLS module for Lua
=======================

[lua-mbedtls] adds support for [Mbed TLS] in Lua:
* SSL/TLS communication + cookie API.
* Message digest and HMAC.
* Base64 encoding/decoding.


Dependencies
------------

+ lua >= 5.1 (or luajit)
+ mbedtls >= 2.7


Building and installing with LuaRocks
-------------------------------------

To build and install, run:

    luarocks make

To install the latest release using [luarocks.org], run:

    luarocks install lua-mbedtls


Building and installing with CMake
----------------------------------

To build and install, run:

    cmake .
    make
    make install

To build for a specific Lua version, set `USE_LUA_VERSION`. For example:

    cmake -D USE_LUA_VERSION=5.1 .

or for LuaJIT:

    cmake -D USE_LUA_VERSION=jit .

To build in a separate directory, replace `.` with a path to the source.


[lua-mbedtls]: https://github.com/neoxic/lua-mbedtls
[Mbed TLS]: https://www.trustedfirmware.org/projects/mbed-tls/
[luarocks.org]: https://luarocks.org
