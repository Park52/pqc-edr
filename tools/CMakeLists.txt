# tools — 프로비저닝·유틸리티

# ML-DSA 신원 키쌍 생성기
add_executable(pqsec_keygen keygen.cpp)
target_link_libraries(pqsec_keygen PRIVATE pqsec_channel)
