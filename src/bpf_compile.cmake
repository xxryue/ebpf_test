

# Generate vmlinux.h

set(GENERATED_VMLINUX_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(BPFOBJECT_VMLINUX_H ${GENERATED_VMLINUX_DIR}/vmlinux.h)
execute_process(COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE ${BPFOBJECT_VMLINUX_H}
        ERROR_VARIABLE VMLINUX_error
        RESULT_VARIABLE VMLINUX_result)
if(${VMLINUX_result} EQUAL 0)
    set(VMLINUX ${BPFOBJECT_VMLINUX_H})
else()
    message(FATAL_ERROR "Failed to dump vmlinux.h from BTF: ${VMLINUX_error}")
endif()
# Get target ARCH
execute_process(
        COMMAND uname -m
        COMMAND sed -e "s/x86_64/x86/" -e "s/aarch64/arm64/" -e "s/ppc64le/powerpc/" -e "s/mips.*/mips/"
        OUTPUT_VARIABLE ARCH_output
        ERROR_VARIABLE ARCH_error
        RESULT_VARIABLE ARCH_result
        OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${ARCH_result} EQUAL 0)
    set(ARCH ${ARCH_output})
    message(STATUS "BPF target arch: ${ARCH}")
else()
    message(FATAL_ERROR "Failed to determine target architecture: ${ARCH_error}")
endif()

macro(ebpf_compile name input)
    message(${name})
    message(${input})
    set(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${input})
    set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
    set(BPF_SKELETON_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.skeleton.h)
    set(OUTPUT_TARGET ${name}_skeleton)

    # Build bpf object file by clang
    add_custom_command(OUTPUT ${BPF_O_FILE}
            COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} -I${GENERATED_VMLINUX_DIR}
            -isystem ${LIBBPF_INCLUDE_DIRS} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
            COMMAND_EXPAND_LISTS
            VERBATIM
            DEPENDS ${BPF_C_FILE}
            COMMENT "[clang] Building BPF object: ${name}"
            )

    # Build BPF skeleton header
    add_custom_command(OUTPUT ${BPF_SKELETON_FILE}
            COMMAND bpftool gen skeleton ${BPF_O_FILE} > ${BPF_SKELETON_FILE}
            VERBATIM
            DEPENDS ${BPF_O_FILE}
            COMMENT "[bpftool] Generate BPF skeleton header file: ${name}"
            )

    add_library(${OUTPUT_TARGET} INTERFACE)
    target_sources(${OUTPUT_TARGET} INTERFACE ${BPF_SKELETON_FILE})
    target_include_directories(${OUTPUT_TARGET} INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    target_include_directories(${OUTPUT_TARGET} SYSTEM INTERFACE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(${OUTPUT_TARGET} INTERFACE ${LIBBPF_LIBRARIES} -lelf -lz)

endmacro()