# BpfObject.cmake
#
# eBPF CO-RE 빌드 파이프라인을 CMake custom command로 엮는 헬퍼.
# 외부 cmake 모듈에 의존하지 않고, 흐름을 직접 노출한다:
#
#   ① /sys/kernel/btf/vmlinux → vmlinux.h            (커널 타입 CO-RE 헤더)
#   ② clang -target bpf        → <name>.bpf.o
#   ③ llvm-strip -g            → (BTF 외 디버그심볼 제거)
#   ④ bpftool gen skeleton     → <name>.skel.h
#
# 결과로 INTERFACE 타깃 <name>_skel 을 만든다. 유저스페이스 실행파일이
# 이 타깃에 링크하면 skeleton 헤더 경로가 include 디렉토리로 딸려온다.

find_program(BPFTOOL_EXE NAMES bpftool REQUIRED)
find_program(CLANG_EXE NAMES clang REQUIRED)
find_program(LLVM_STRIP_EXE NAMES llvm-strip REQUIRED)

# libbpf (헤더/라이브러리) — pkg-config로 해결
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# pkg-config include 디렉토리를 clang -I 플래그 리스트로 변환
set(LIBBPF_INCLUDE_DIRS_ARG "")
foreach(inc ${LIBBPF_INCLUDE_DIRS})
  list(APPEND LIBBPF_INCLUDE_DIRS_ARG "-I${inc}")
endforeach()

# 현재 아키텍처 → clang BPF 타깃 매크로 (__TARGET_ARCH_x86 등)
execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH_RAW OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX REPLACE "x86_64" "x86" BPF_ARCH "${ARCH_RAW}")
string(REGEX REPLACE "aarch64" "arm64" BPF_ARCH "${BPF_ARCH}")

# bpf_object(<name> SOURCE <path/to/xxx.bpf.c>)
#
# vmlinux.h 생성부터 skeleton 까지, 소비하는 커맨드와 같은 디렉토리 스코프에서
# 만든다. (Make generator 는 다른 디렉토리에서 생성된 파일 의존성을 자동으로
# 연결하지 못하므로.)
function(bpf_object name)
  cmake_parse_arguments(ARG "" "SOURCE" "" ${ARGN})
  if(NOT ARG_SOURCE)
    message(FATAL_ERROR "bpf_object(${name}): SOURCE 인자 필요")
  endif()
  get_filename_component(src_abs ${ARG_SOURCE} ABSOLUTE)

  set(vmlinux_h ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
  set(bpf_obj   ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
  set(skel_h    ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)

  # ① 커널 BTF → vmlinux.h
  add_custom_command(
    OUTPUT ${vmlinux_h}
    COMMAND ${BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c > ${vmlinux_h}
    COMMENT "[bpf] vmlinux.h 생성 (커널 BTF에서 덤프)"
    VERBATIM)

  # ② clang → .bpf.o, ③ llvm-strip
  add_custom_command(
    OUTPUT ${bpf_obj}
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
            -I${CMAKE_CURRENT_BINARY_DIR}    # vmlinux.h
            -I${CMAKE_SOURCE_DIR}/common     # 공통 스키마
            ${LIBBPF_INCLUDE_DIRS_ARG}
            -c ${src_abs} -o ${bpf_obj}
    COMMAND ${LLVM_STRIP_EXE} -g ${bpf_obj}
    DEPENDS ${src_abs} ${vmlinux_h}
    COMMENT "[bpf] ${name}.bpf.c → ${name}.bpf.o (clang -target bpf)"
    VERBATIM)

  # ④ bpftool gen skeleton → .skel.h
  add_custom_command(
    OUTPUT ${skel_h}
    COMMAND ${BPFTOOL_EXE} gen skeleton ${bpf_obj} > ${skel_h}
    DEPENDS ${bpf_obj}
    COMMENT "[bpf] ${name}.skel.h 생성 (skeleton)"
    VERBATIM)

  add_custom_target(${name}_skel_gen DEPENDS ${skel_h})

  add_library(${name}_skel INTERFACE)
  add_dependencies(${name}_skel ${name}_skel_gen)
  target_include_directories(${name}_skel INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
  target_include_directories(${name}_skel INTERFACE ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(${name}_skel INTERFACE ${LIBBPF_LIBRARIES})
  target_link_directories(${name}_skel INTERFACE ${LIBBPF_LIBRARY_DIRS})
endfunction()
