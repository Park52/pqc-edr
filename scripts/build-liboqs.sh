#!/usr/bin/env bash
#
# liboqs 를 로컬 prefix 에 빌드·설치한다 (시스템 전역 설치 X, sudo 불필요).
#   - ML-KEM(기밀성) + ML-DSA(인증) 만 최소 빌드해 시간 절약 (OQS_MINIMAL_BUILD)
#   - liboqs 내부 crypto 사용, OpenSSL 의존 OFF → 이 단계에선 libssl-dev 불필요
#
# 산출물:
#   third_party/liboqs/{include,lib}   (CMake 에서 이 prefix 를 참조)
#
# 재실행 안전(idempotent). 이미 설치돼 있으면 --force 없이는 건너뛴다.
set -euo pipefail

LIBOQS_VERSION="0.15.0"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP_DIR="${REPO_ROOT}/third_party"
SRC_DIR="${TP_DIR}/liboqs-src"
BUILD_DIR="${SRC_DIR}/build"
PREFIX="${TP_DIR}/liboqs"

if [[ "${1:-}" != "--force" && -f "${PREFIX}/lib/liboqs.so" ]]; then
  echo "[build-liboqs] 이미 설치됨: ${PREFIX} (다시 빌드하려면 --force)"
  exit 0
fi

mkdir -p "${TP_DIR}"

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  echo "[build-liboqs] clone liboqs ${LIBOQS_VERSION}"
  git clone --depth 1 --branch "${LIBOQS_VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git "${SRC_DIR}"
fi

echo "[build-liboqs] configure (ML-KEM-768 + ML-DSA-65, OpenSSL OFF)"
cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65"

echo "[build-liboqs] build & install"
cmake --build "${BUILD_DIR}" --parallel
cmake --install "${BUILD_DIR}"

echo "[build-liboqs] 완료:"
ls -la "${PREFIX}/lib/" | grep -E "liboqs" || true
echo "  헤더: ${PREFIX}/include/oqs/oqs.h"
