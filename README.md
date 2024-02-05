SCION SNET Bindings for C and C++
=================================

### Build
CMake build options:
- `GO_BINARY` Path to the go executable.
- `BUILD_STATIC_LIBS` Build a static library.
- `BUILD_SHARED_LIBS` Build a shared/dynamic library and link examples against
  it instead of statically linking SNET.
- `BUILD_EXAMPLES` Build examples programs.

#### Linux
Release:
```bash
mkdir -p build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_STATIC_LIBS=ON -B build/release
cmake --build build/release
```

Debug:
```bash
mkdir -p build/debug
cmake -D CMAKE_BUILD_TYPE=Debug -D BUILD_STATIC_LIBS=ON -B build/debug
cmake --build build/debug
```

#### Windows 10/11 (MSYS2 MinGW)
Install [MSYS2](https://www.msys2.org/) and Go. The following MSYS2 packets are
required:
```bash
pacman -Sy
pacman -S \
  mingw-w64-ucrt-x86_64-gcc   \
  mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-ninja \
  mingw-w64-ucrt-x86_64-asio  \
  mingw-w64-ucrt-x86_64-doctest
```

Open an MSYS2 UCRT64 environment and navigate to the project root (Windows drive
letters are available as `/c` and so on). Set `GO_BINARY` to t
```bash
mkdir build
cmake -D BUILD_STATIC_LIBS=ON -D GO_BINARY="$PROGRAMFILES/Go/bin/go.exe" -G 'Ninja Multi-Config' -B build
# Release:
cmake --build build --config Release
# Debug:
cmake --build build --config Debug
```

### Tests
Some tests can be run by invoking the "test" target in make or ninja.

#### Example applications
The `examples` directory contains simple echo servers/clients demonstrating both
synchronous and asynchronous IO.

Usage example (assuming the `tiny4.topo` topology from the SCION repository):
```bash
# Synchronous API
# Server
snet-echo -sciond 127.0.0.19:30255 -local 127.0.0.1:5000
# Client
snet-echo -sciond 127.0.0.27:30255 -local 127.0.0.1:5001 -remote [1-ff00:0:111,127.0.0.1]:5000

# Asynchronous API
# Server
snet-echo-async -sciond 127.0.0.19:30255 -local 127.0.0.1:5000
# Client
snet-echo-async -sciond 127.0.0.27:30255 -local 127.0.0.1:5001 -remote [1-ff00:0:111,127.0.0.1]:5000
```
