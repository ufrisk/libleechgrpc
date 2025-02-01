# Copyright 2018 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# cmake build file for C++ helloworld example.
# Assumes protobuf and gRPC have been installed using cmake.
# See cmake_externalproject/CMakeLists.txt for all-in-one cmake build
# that automatically builds all the dependencies before building helloworld.

cmake_minimum_required(VERSION 3.8)

project(leechgrpc C CXX)

include(./common.cmake)

#set(OPENSSL_USE_STATIC_LIBS TRUE)
#find_package(OpenSSL REQUIRED) 

# Proto file
get_filename_component(hw_proto "./proto/leechgrpc.proto" ABSOLUTE)
get_filename_component(hw_proto_path "${hw_proto}" PATH)

# Generated sources
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/leechgrpc.pb.cc")
set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/leechgrpc.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/leechgrpc.grpc.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/leechgrpc.grpc.pb.h")
add_custom_command(
      OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}" "${hw_grpc_srcs}" "${hw_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${hw_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
      DEPENDS "${hw_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# hw_grpc_proto
add_library(hw_grpc_proto
  ${hw_grpc_srcs}
  ${hw_grpc_hdrs}
  ${hw_proto_srcs}
  ${hw_proto_hdrs})
target_link_libraries(hw_grpc_proto
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

# --- [ Final shared library ] -----------------------------------------------
# We now create a shared library that pulls in everything statically 
# (except for system libs). On Linux, you need position-independent code 
# for all objects, which we enabled earlier with CMAKE_POSITION_INDEPENDENT_CODE=TRUE 
# when building gRPC and with the default setting for these libraries here.

add_library(leechgrpc SHARED "${CMAKE_CURRENT_SOURCE_DIR}/leechgrpc_client.cc" "${CMAKE_CURRENT_SOURCE_DIR}/leechgrpc_server.cc" "${CMAKE_CURRENT_SOURCE_DIR}/oscompatibility.cc" "${CMAKE_CURRENT_SOURCE_DIR}/util.cc")
# Link the static pieces
target_link_libraries(leechgrpc
    PRIVATE
        hw_grpc_proto
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF}
#        OpenSSL::SSL
#        OpenSSL::Crypto
)

# Provide an soname for the library if desired:
set_target_properties(leechgrpc PROPERTIES
    OUTPUT_NAME "leechgrpc"
    SOVERSION "1"
)

