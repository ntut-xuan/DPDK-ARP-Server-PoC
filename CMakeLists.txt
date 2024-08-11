# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

cmake_minimum_required(VERSION 3.10)
project(dpdk-arp-server)

# Binary name
set(APP dpdk-arp-server)

# All source are stored in SRCS-y
set(SRCS-y main.cpp)

set (PKGCONF pkg-config)

# Deal with spdlog
include(FetchContent)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1 # or the version you want to use
)
FetchContent_MakeAvailable(spdlog)
set (SPDLOG_LIBRARIES "${CMAKE_BINARY_DIR}/_deps/spdlog-src/include")

# Check dpdk lib is exists or not.
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

if(NOT DPDK_FOUND)
    message(FATAL_ERROR "No installation of DPDK found")
endif()

# Set compilation flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 ${LIBDPDK_CFLAGS} -DALLOW_EXPERIMENTAL_API -g -mssse3")

# Create build folder
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/build)

add_executable(${APP}-shared ${SRCS-y})
target_link_libraries(${APP}-shared PUBLIC ${DPDK_LIBRARIES})
target_include_directories(${APP}-shared PRIVATE ${SPDLOG_LIBRARIES})
set_target_properties(${APP}-shared PROPERTIES OUTPUT_NAME "${CMAKE_BINARY_DIR}/build/${APP}-shared")

add_executable(${APP}-static ${SRCS-y})
target_link_libraries(${APP}-static PUBLIC ${DPDK_STATIC_LIBRARIES})
target_include_directories(${APP}-static PRIVATE ${SPDLOG_LIBRARIES})
set_target_properties(${APP}-static PROPERTIES OUTPUT_NAME "${CMAKE_BINARY_DIR}/build/${APP}-static")
