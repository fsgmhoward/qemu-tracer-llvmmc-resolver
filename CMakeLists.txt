cmake_minimum_required(VERSION 3.13)
project(resolver)

set(CMAKE_CXX_STANDARD 17)

set (CMAKE_VERBOSE_MAKEFILE ON)

set (Disassem_VERSION_MAJOR 1)
set (Disassem_VERSION_MINOR 1)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

## LLVM 8

find_package(LLVM 8 REQUIRED CONFIG)

message(STATUS "LLVM_VERSION: ${LLVM_VERSION}")
message(STATUS "LLVM_INCLUDE_DIRS: ${LLVM_INCLUDE_DIRS}")
message(STATUS "LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

## CAPNP

find_package(CapnProto REQUIRED)

message(STATUS "CAPNP_INCLUDE_DIRS: ${CAPNP_INCLUDE_DIRS}")
message(STATUS "CAPNP_LIBS: ${CAPNP_LIBRARIES}")

capnp_generate_cpp(CAPNP_IN_SRCS CAPNP_IN_HDRS capnp/resolver_in_cpp.capnp)
capnp_generate_cpp(CAPNP_OUT_SRCS CAPNP_OUT_HDRS capnp/resolver_out_cpp.capnp)

include_directories(${CAPNP_INCLUDE_DIRS})
add_definitions(${CAPNP_DEFINITIONS})

add_executable(resolver resolver.cpp ${CAPNP_IN_SRCS} ${CAPNP_OUT_SRCS})

# static link
llvm_map_components_to_libnames(llvm_libs all)
if (APPLE)
    target_link_libraries(resolver ${llvm_libs} ${CAPNP_LIBRARIES})
elseif (UNIX)
    target_link_libraries(resolver LLVM ${CAPNP_LIBRARIES})
endif (APPLE)


# dynamic link (This does not really work for me)
# llvm_config(resolver USE_SHARED)