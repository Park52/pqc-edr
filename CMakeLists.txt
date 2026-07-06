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
option(BUILD_ANALYZER "Build the LLM analyzer (Week 3+)" OFF)

# --- 공통 헤더 (스키마 등) ---------------------------------------------------
add_library(pqsec_common INTERFACE)
target_include_directories(pqsec_common INTERFACE ${CMAKE_SOURCE_DIR}/common)

# --- eBPF 빌드 헬퍼 함수 -----------------------------------------------------
include(${CMAKE_SOURCE_DIR}/cmake/BpfObject.cmake)

# --- 서브 컴포넌트 -----------------------------------------------------------
if(BUILD_AGENT)
  add_subdirectory(agent)
endif()

if(BUILD_ANALYZER)
  add_subdirectory(analyzer)
endif()
