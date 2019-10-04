cmake_minimum_required(VERSION 2.8.12)
project(xdpnetload)

#add_compile_options("-std=c99")
#add_compile_options("-Wno-format-security")
add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-Wundef")
#add_compile_options("-Wpointer-arith")
add_compile_options("-Wcast-align")
add_compile_options("-Wwrite-strings")
#add_compile_options("-Wcast-qual")
#add_compile_options("-Wswitch-default")
#add_compile_options("-Wswitch-enum")
#add_compile_options("-Wconversion")
add_compile_options("-Wunreachable-code")
#add_compile_options("-Wformat=2")

add_compile_options("-Wno-error=unused-parameter")
add_compile_options("-Wno-error=sign-conversion")
add_compile_options("-Wno-error=sign-compare")
add_compile_options("-Wno-error=implicit-fallthrough")
add_compile_options("-Wno-error=discarded-qualifiers")

#add_compile_options("-Wstrict-overflow=5")
#add_compile_options("-Wdisabled-optimization")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# eBPF/XDP kernel part

find_package(LibElf REQUIRED)
include_directories(${LIBELF_INCLUDE_DIRS})

find_program(CLANG_COMPILER clang)
find_program(LLVM_COMPILER llc)

set(KERNEL_INCLUDE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  )

set(KERNEL_DEF
  __KERNEL__
  __ASM_SYSREG_H
  __BPF_TRACING__
  __TARGET_ARCH_$(ARCH)

  )

list(TRANSFORM KERNEL_INCLUDE PREPEND -I)
list(TRANSFORM KERNEL_DEF PREPEND -D)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.ll
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xnl_kernel.c
  COMMAND ${CLANG_COMPILER}
  ${KERNEL_INCLUDE} ${KERNEL_DEF}
  -target bpf
  -O2 -Wall -g -c
  -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types
  -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-compare -Wno-unknown-warning-option
  -Wno-address-of-packed-member -Werror
  -S -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/xnl_kernel.c
  -o ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.ll
  )

add_custom_target(xnl_kernel_ll ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.ll)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.o
  COMMAND ${LLVM_COMPILER}
  -march=bpf -filetype=obj -o ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.o
  ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.ll
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.ll
  )

add_custom_target(xnl_kernel ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xnl_kernel.o)

#add_dependencies(xnl_kernel xnl_kernel_ll)

#add_custom_target(xnl_kernel ALL DEPENDS xnl_kernel_o)

# user-space

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB libbpf_sources "${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/*.c")
add_library(bpf STATIC ${libbpf_sources})
set_target_properties(bpf PROPERTIES OUTPUT_NAME bpf)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/libbpf/src/build"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/libbpf/src"
  COMMAND make DESTDIR=build install_headers
  )

target_include_directories(bpf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/build/usr/include)
target_include_directories(bpf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/linux)
target_include_directories(bpf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
target_include_directories(bpf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)

set(BUILD_EXAMPLES OFF)
set(BUILD_STATIC ON)
set(CMAKE_STATIC_LIBRARY_PREFIX "")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libubox)

set(UBUS_UNIX_SOCKET "/var/run/ubus.sock")
set(UBUS_MAX_MSGLEN 1048576)

add_definitions(-DUBUS_UNIX_SOCKET="${UBUS_UNIX_SOCKET}")
add_definitions(-DUBUS_MAX_MSGLEN=${UBUS_MAX_MSGLEN})

add_library(ubus STATIC ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus.c ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus-io.c ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus-obj.c ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus-sub.c ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus-req.c ${CMAKE_CURRENT_SOURCE_DIR}/ubus/libubus-acl.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ubus)

set(SOURCES xdpnetload.c)

set(LIBS ubus bpf)

add_custom_target(install_bpf_headers DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libbpf/src/build")

add_executable(xdpnetload ${SOURCES})
target_link_libraries(xdpnetload ${LIBS} ${LIBELF_LIBRARIES} ${CMAKE_CURRENT_SOURCE_DIR}/libubox/libubox.a)

target_include_directories(xdpnetload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/build/usr/include)
target_include_directories(xdpnetload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
target_include_directories(xdpnetload PRIVATE ${LIBELF_INCLUDE_DIRS})
