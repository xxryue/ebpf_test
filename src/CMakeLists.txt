cmake_minimum_required(VERSION 3.10)

project(ebpf_test)

# tell cmake where to find bpf_compile module
list(APPEND CMAKE_MODULE_PATH .)
include(bpf_compile.cmake)
file(GLOB ebpf_apps *.bpf.c)

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


