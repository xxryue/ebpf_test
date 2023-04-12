macro(ebpf_compile name input)
    message(${name})
    message(${input})
    set(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${input})
    set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
    set(BPF_SKELETON_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.skeleton.h)
    set(OUTPUT_TARGET ${name}_skeleton)

    # Build bpf object file by clang
    add_custom_command(OUTPUT ${BPF_O_FILE}
            COMMAND clang -g -O2 -target bpf -c ${BPF_C_FILE} -o ${BPF_O_FILE}
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
    target_link_libraries(${OUTPUT_TARGET} INTERFACE -lbpf -lelf -lz)

endmacro()