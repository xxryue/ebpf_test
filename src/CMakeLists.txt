cmake_minimum_required(VERSION 3.16)

project(ebpf_test)

include(ExternalProject)
EXTERNALPROJECT_ADD(libbpf
        PREFIX libbpf
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libbpf/src
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
        INCLUDEDIR=
        LIBDIR=
        UAPIDIR=
        install install_uapi_headers
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ""
        STEP_TARGETS build
        )

# tell cmake where to find bpf_compile module
list(APPEND CMAKE_MODULE_PATH .)
include(bpf_compile.cmake)
file(GLOB ebpf_apps *.bpf.c)

set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

foreach(app ${ebpf_apps})
    get_filename_component(app_name ${app} NAME_WE)
    ebpf_compile(${app_name} ${app_name}.bpf.c)
endforeach()
add_executable(ebpf_test main.c common.h)

foreach(app ${ebpf_apps})
    get_filename_component(app_name ${app} NAME_WE)
    target_link_libraries(ebpf_test ${app_name}_skeleton)
endforeach()


add_subdirectory(udp_app)
