cmake_minimum_required(VERSION 3.16)
project(pqsec_pipeline LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# --- 옵션 -------------------------------------------------------------------
option(BUILD_AGENT "Build the eBPF collector agent" ON)
option(BUILD_ANALYZER "Build the LLM analyzer (Week 3+)" ON)
option(BUILD_CRYPTO "Build the PQC secure channel + examples" ON)

# --- 테스트 (셀프테스트 실행파일을 ctest 로 묶음: `ctest --test-dir build`) -------
enable_testing()

# --- liboqs (scripts/build-liboqs.sh 로 로컬 빌드된 prefix) -------------------
set(LIBOQS_PREFIX ${CMAKE_SOURCE_DIR}/third_party/liboqs)
list(APPEND CMAKE_PREFIX_PATH ${LIBOQS_PREFIX})

# --- 공통 헤더 (스키마 등) ---------------------------------------------------
add_library(pqsec_common INTERFACE)
target_include_directories(pqsec_common INTERFACE ${CMAKE_SOURCE_DIR}/common)

# --- vendored nlohmann/json (헤더온리) ---------------------------------------
add_library(pqsec_json INTERFACE)
target_include_directories(pqsec_json INTERFACE ${CMAKE_SOURCE_DIR}/third_party/json)

# --- eBPF 빌드 헬퍼 함수 (agent 빌드 시에만 — 컨테이너 빌드는 clang/bpftool 불필요) ---
if(BUILD_AGENT)
  include(${CMAKE_SOURCE_DIR}/cmake/BpfObject.cmake)
endif()

# --- 서브 컴포넌트 -----------------------------------------------------------
# crypto(pqsec_channel)를 먼저 — agent/analyzer 가 링크한다.
if(BUILD_CRYPTO)
  add_subdirectory(crypto)
  add_subdirectory(tools)
endif()

if(BUILD_AGENT)
  add_subdirectory(agent)
endif()

if(BUILD_ANALYZER)
  add_subdirectory(analyzer)
endif()
