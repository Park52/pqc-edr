// crypto/src/record.cpp — AES-256-GCM record layer (OpenSSL EVP)

#include "pqsec/record.h"

#include <openssl/evp.h>

#include <cstring>

namespace pqsec {

namespace {

[[noreturn]] void fail(const char *what) { throw RecordError(std::string("record: ") + what); }

// nonce = iv_base XOR (0^4 ‖ seq_be64)
Bytes make_nonce(const Bytes &iv_base, uint64_t seq) {
    Bytes nonce = iv_base; // 12B
    for (int i = 0; i < 8; ++i) {
        uint8_t seq_byte = static_cast<uint8_t>(seq >> (8 * (7 - i)));
        nonce[kIvLen - 8 + i] ^= seq_byte;
    }
    return nonce;
}

void put_u16(Bytes &b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xff));
}

// AES-256-GCM 암호화. aad 인증, tag 를 ciphertext 뒤에 붙여 반환.
Bytes aes_gcm_seal(const Bytes &key, const Bytes &nonce, const Bytes &aad, const Bytes &pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        fail("cipher ctx 생성 실패");

    Bytes out(pt.size() + kGcmTagLen);
    int len = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1;
    int ct_len = 0;
    if (ok)
        ok = EVP_EncryptUpdate(ctx, out.data(), &len, pt.data(), pt.size()) == 1;
    if (ok) {
        ct_len = len;
        ok = EVP_EncryptFinal_ex(ctx, out.data() + len, &len) == 1;
    }
    if (ok) {
        ct_len += len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagLen,
                                 out.data() + ct_len) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        fail("AES-256-GCM 암호화 실패");
    out.resize(ct_len + kGcmTagLen);
    return out;
}

// AES-256-GCM 복호. tag 검증 실패 시 RecordError (fail-closed).
Bytes aes_gcm_open(const Bytes &key, const Bytes &nonce, const Bytes &aad,
                   const uint8_t *ct, size_t ct_len, const uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        fail("cipher ctx 생성 실패");

    Bytes pt(ct_len);
    int len = 0;
    int pt_len = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty())
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1;
    if (ok)
        ok = EVP_DecryptUpdate(ctx, pt.data(), &len, ct, ct_len) == 1;
    if (ok) {
        pt_len = len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen,
                                 const_cast<uint8_t *>(tag)) == 1;
    }
    // Final 이 태그 검증. 실패하면 <=0.
    if (ok)
        ok = EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        fail("GCM 태그 검증 실패 (변조/키불일치/순서오류)");
    pt.resize(pt_len + len);
    return pt;
}

} // namespace

RecordSender::RecordSender(Bytes key, Bytes iv_base)
    : key_(std::move(key)), iv_base_(std::move(iv_base)) {
    if (key_.size() != kAesKeyLen || iv_base_.size() != kIvLen)
        fail("송신기 키/IV 길이 오류");
}

Bytes RecordSender::seal(const Bytes &plaintext) {
    if (seq_ == UINT64_MAX)
        fail("시퀀스 소진 (nonce 재사용 방지)"); // fail-closed
    if (plaintext.size() > 0xffff - kGcmTagLen)
        fail("plaintext 가 레코드 한도 초과");

    // 레코드 헤더(길이)를 먼저 만들어 AAD 로 인증
    uint16_t payload_len = static_cast<uint16_t>(plaintext.size() + kGcmTagLen);
    Bytes header;
    put_u16(header, payload_len);

    Bytes nonce = make_nonce(iv_base_, seq_);
    Bytes ct_tag = aes_gcm_seal(key_, nonce, header, plaintext);
    ++seq_;

    Bytes record = header;
    record.insert(record.end(), ct_tag.begin(), ct_tag.end());
    return record;
}

RecordReceiver::RecordReceiver(Bytes key, Bytes iv_base)
    : key_(std::move(key)), iv_base_(std::move(iv_base)) {
    if (key_.size() != kAesKeyLen || iv_base_.size() != kIvLen)
        fail("수신기 키/IV 길이 오류");
}

Bytes RecordReceiver::open(const Bytes &record) {
    if (seq_ == UINT64_MAX)
        fail("시퀀스 소진");
    if (record.size() < 2 + kGcmTagLen)
        fail("레코드가 너무 짧음");

    uint16_t payload_len = static_cast<uint16_t>(record[0] << 8 | record[1]);
    if (record.size() != 2u + payload_len)
        fail("레코드 길이 헤더 불일치");
    if (payload_len < kGcmTagLen)
        fail("payload 가 태그보다 짧음");

    Bytes header = {record[0], record[1]}; // AAD
    const uint8_t *ct = record.data() + 2;
    size_t ct_len = payload_len - kGcmTagLen;
    const uint8_t *tag = ct + ct_len;

    Bytes nonce = make_nonce(iv_base_, seq_);
    Bytes pt = aes_gcm_open(key_, nonce, header, ct, ct_len, tag);
    ++seq_;
    return pt;
}

} // namespace pqsec
