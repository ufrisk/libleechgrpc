libleechgrpc
============

libleechgrpc is a wrapper around gRPC to allow PCILeech/LeechCore/MemProcFS to access remote LeechAgent instances in a platform independent way.

libleechgrpc supports two authentication modes:
* unauthenticated with no transport encryption - i.e. insecure mode.
* mutually authenticated mTLS connection - i.e. secure mode.

libleechgrpc is by default statically linked and shouldn't require additional libraries.



Building (Windows):
===================
```
#
# Install grpc-static via vcpkg
# This will take a decent while since it's compiling etc.
#
git clone https://github.com/microsoft/vcpkg.git C:\src\vcpkg
cd C:\src\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
.\vcpkg install grpc:x64-windows-static protobuf:x64-windows-static

#
# Generate gRPC stubs using the installed packages.
#
cd C:\src\leechgrpc\leechgrpc\
C:\src\vcpkg\installed\x64-windows-static\tools\protobuf\protoc.exe --proto_path=proto --cpp_out=generated --grpc_out=generated --plugin=protoc-gen-grpc="C:\src\vcpkg\installed\x64-windows\tools\grpc\grpc_cpp_plugin.exe" leechgrpc.proto

#
# Build leechgrpc in Visual Studio or by using the Visual Studio 2022 command prompt:
#
cd C:\src\leechgrpc\
MSBuild libleechgrpc.sln /t:Rebuild /property:Configuration=Release /property:Platform=x64"
```



Building (Linux):
===================
```bash
# export local bin directory to path
export MY_INSTALL_DIR=$HOME/.local
export PATH="$MY_INSTALL_DIR/bin:$PATH"

# install build tools
sudo apt update
sudo apt install git build-essential autoconf libtool pkg-config

# clone gRPC from github
mkdir -p $HOME/.local
mkdir -p $HOME/.local/build
cd $HOME/.local/build
git clone --recurse-submodules -b v1.66.0 https://github.com/grpc/grpc.git
cd grpc
git submodule update --init --recursive
mkdir -p cmake/build
cd cmake/build

# get cmake (since linux cmake may be too old)
wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3-linux-x86_64.sh
sh cmake-linux.sh -- --skip-license --prefix=$MY_INSTALL_DIR
rm cmake-linux.sh
export PATH="$HOME/.local/bin:$PATH"
cmake --version

# build gRPC as a static library and install locally
cmake \
   -DCMAKE_BUILD_TYPE=Release \
   -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
   -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
   -DBUILD_SHARED_LIBS=OFF \
   -DgRPC_INSTALL=ON \
   -DgRPC_BUILD_TESTS=OFF \
   -DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF \
   -DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF \
   -DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF \
   -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
   -DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF \
   -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF \
   ../..
make -j 4
make install

# clone libleechgrpc from github
mkdir -p ~/Github/
cd ~/Github/
git clone https://github.com/ufrisk/libleechgrpc
mkdir -p ~/Github/libleechgrpc/libleechgrpc/build
cd ~/Github/libleechgrpc/libleechgrpc/build

# build libleechgrpc.so
cmake \
   -DCMAKE_PREFIX_PATH="$MY_INSTALL_DIR" \
   -DCMAKE_CXX_FLAGS="-DLINUX -fPIC -O2 -ffunction-sections -fdata-sections -flto" \
   -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS="-flto -Wl,--gc-sections" \
   ..
make -j 4

# libleechgrpc.so should now have been built if everything was successful!
```
