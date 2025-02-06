# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2020-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#

cmake_minimum_required(VERSION 3.5)
project(profinet-eval)

set(VERSION "5.2")

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wshadow -std=gnu99 -Wvla")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wshadow -std=c++14 -Wvla")
add_definitions(-D_GNU_SOURCE)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

pkg_search_module(YAML yaml-0.1 REQUIRED)
pkg_search_module(LIBBPF libbpf REQUIRED)
pkg_search_module(LIBXDP libxdp REQUIRED)
pkg_search_module(LIBCRYPTO libcrypto>=3.0 REQUIRED)

check_symbol_exists(SO_BUSY_POLL "sys/socket.h" HAVE_SO_BUSY_POLL)
check_symbol_exists(SO_PREFER_BUSY_POLL "sys/socket.h" HAVE_SO_PREFER_BUSY_POLL)
check_symbol_exists(SO_BUSY_POLL_BUDGET "sys/socket.h" HAVE_SO_BUSY_POLL_BUDGET)

add_executable(reference
  src/reference.c
  src/config.c
  src/utils.c
  src/log.c
  src/logviamqtt.c
  src/stat.c
  src/ring_buffer.c
  src/thread.c
  src/tsn_thread.c
  src/rtc_thread.c
  src/rta_thread.c
  src/dcp_thread.c
  src/lldp_thread.c
  src/udp_thread.c
  src/layer2_thread.c
  src/net.c
  src/xdp.c
  src/tx_time.c
  src/security.c
  src/packet.c
  src/hist.c)
add_executable(mirror
  src/mirror.c
  src/config.c
  src/utils.c
  src/log.c
  src/logviamqtt.c
  src/stat.c
  src/ring_buffer.c
  src/thread.c
  src/tsn_thread.c
  src/rtc_thread.c
  src/rta_thread.c
  src/dcp_thread.c
  src/lldp_thread.c
  src/udp_thread.c
  src/layer2_thread.c
  src/net.c
  src/xdp.c
  src/tx_time.c
  src/security.c
  src/packet.c
  src/hist.c)

option(WITH_MQTT, "Enable/Disable logging via MQTT" OFF)
if (WITH_MQTT)
  pkg_search_module(MOSQUITTO libmosquitto REQUIRED)
  target_link_libraries(reference ${MOSQUITTO_LIBRARIES})
  target_link_libraries(mirror ${MOSQUITTO_LIBRARIES})
  target_include_directories(reference PUBLIC ${MOSQUITTO_INCLUDE_DIRS})
  target_include_directories(mirror PUBLIC ${MOSQUITTO_INCLUDE_DIRS})
endif()

target_link_libraries(reference Threads::Threads)
target_link_libraries(reference ${YAML_LIBRARIES})
target_link_libraries(reference ${LIBBPF_LIBRARIES})
target_link_libraries(reference ${LIBXDP_LIBRARIES})
target_link_libraries(reference ${LIBCRYPTO_LIBRARIES})

target_link_libraries(mirror Threads::Threads)
target_link_libraries(mirror ${YAML_LIBRARIES})
target_link_libraries(mirror ${LIBBPF_LIBRARIES})
target_link_libraries(mirror ${LIBXDP_LIBRARIES})
target_link_libraries(mirror ${LIBCRYPTO_LIBRARIES})

target_include_directories(reference PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(reference PRIVATE "src")
target_include_directories(reference PUBLIC ${YAML_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBXDP_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBCRYPTO_INCLUDE_DIRS})
target_include_directories(mirror PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(mirror PRIVATE "src")
target_include_directories(mirror PUBLIC ${YAML_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBXDP_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBCRYPTO_INCLUDE_DIRS})

set(INSTALL_EBPF_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rtc-testbench/ebpf)
configure_file(
  "${PROJECT_SOURCE_DIR}/app_config.in"
  "${PROJECT_BINARY_DIR}/app_config.h"
  )
include_directories("${PROJECT_BINARY_DIR}")

#
# Add code for compiling XDP eBPF programes.
#
set(ASM_INCLUDE "/usr/include/${CMAKE_C_LIBRARY_ARCHITECTURE}")
set(CLANG_FLAGS -S --target=bpf -D __BPF_TRACING__ -Wall -O2 -fno-stack-protector -emit-llvm -g -I ${ASM_INCLUDE})
set(LLC_FLAGS -march=bpf -filetype=obj)

function(add_xdp_prog name)
  add_custom_target(${name}_stage1 ALL
    COMMAND clang ${CLANG_FLAGS} -c -o ${name}.ll ${name}.c
    DEPENDS reference
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    SOURCES src/${name}.c
  )

  add_custom_target(${name}_stage2 ALL
    COMMAND llc ${LLC_FLAGS} -o ${CMAKE_BINARY_DIR}/${name}.o ${name}.ll
    DEPENDS ${name}_stage1
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    SOURCES src/${name}.c
  )

  install(FILES ${CMAKE_BINARY_DIR}/${name}.o DESTINATION ${CMAKE_INSTALL_LIBDIR}/rtc-testbench/ebpf)
endfunction()

add_xdp_prog(xdp_kern_profinet_vid100)
add_xdp_prog(xdp_kern_opcua_vid100)
add_xdp_prog(xdp_kern_profinet_vid200)
add_xdp_prog(xdp_kern_opcua_vid200)
add_xdp_prog(xdp_kern_opcua_vid300)
add_xdp_prog(xdp_kern_avtp_vid400)

install(TARGETS reference DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT binaries)
install(TARGETS mirror DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT binaries)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/tests/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/rtc-testbench/tests)
