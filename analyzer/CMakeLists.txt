# analyzer — LLM 이상탐지 (Week 3)
#
# 현재: 파이프라인 코어(prefilter/alert/mock LLM) + 셀프테스트.
# 이후: 실 Claude API 클라이언트(libcurl) + PQC 채널 수신 데몬.

find_package(CURL REQUIRED) # Claude API raw HTTPS 호출

add_library(analyzer_core STATIC
  src/prefilter.cpp
  src/alert.cpp
  src/llm_client.cpp
  src/llm_client_claude.cpp
  src/pipeline.cpp)
target_include_directories(analyzer_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(analyzer_core PUBLIC pqsec_common pqsec_json CURL::libcurl)

# 분류 파이프라인 셀프테스트 (오프라인, mock LLM)
add_executable(analyzer_selftest src/analyzer_selftest.cpp)
target_link_libraries(analyzer_selftest PRIVATE analyzer_core)

# 실 Claude API 경로 수동 점검 (ANTHROPIC_API_KEY 필요)
add_executable(llm_probe src/llm_probe.cpp)
target_link_libraries(llm_probe PRIVATE analyzer_core)

# analyzer 데몬 (PQC 채널 수신 → 분류 → alert)
add_executable(analyzer src/main.cpp)
target_link_libraries(analyzer PRIVATE analyzer_core pqsec_channel)
