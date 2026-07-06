# crypto — PQC 보안 채널 (하이브리드 KEM, record layer) + 예제
#
# 현재: PQC 래퍼(ML-KEM/ML-DSA) + 핸드셰이크 와이어 포맷.
# 이후: 하이브리드 KEM(X25519·HKDF) + record layer(AES-256-GCM) — libssl-dev 필요.

find_package(liboqs REQUIRED)

# 보안 채널 라이브러리 (agent/analyzer 공유 예정)
add_library(pqsec_channel STATIC
  src/pqc_kem.cpp
  src/pqc_sig.cpp
  src/wire.cpp)
target_include_directories(pqsec_channel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(pqsec_channel PUBLIC OQS::oqs)

# ML-KEM keypair/encaps/decaps 왕복 데모
add_executable(mlkem_demo examples/mlkem_demo.cpp)
target_link_libraries(mlkem_demo PRIVATE OQS::oqs)

# 채널 셀프테스트 (ML-KEM/ML-DSA/와이어)
add_executable(channel_selftest examples/channel_selftest.cpp)
target_link_libraries(channel_selftest PRIVATE pqsec_channel OQS::oqs)
