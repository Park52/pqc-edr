# Agent — eBPF collector
#
# ① collector.bpf.c → skeleton (bpf_object 헬퍼)
# ② main.cpp 가 skeleton 을 include, libbpf 링크

bpf_object(collector SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/collector.bpf.c)

add_executable(agent src/main.cpp)
target_link_libraries(agent PRIVATE collector_skel pqsec_common pqsec_channel)
