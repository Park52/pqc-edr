// crypto/src/identity.cpp — 신원 파일 저장/로드

#include "pqsec/identity.h"
#include "pqsec/pqc.h"

#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

namespace pqsec {

void write_bytes_file(const std::string &path, const Bytes &data, bool restrict_perms) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("파일 열기 실패: " + path);
    if (!data.empty())
        f.write(reinterpret_cast<const char *>(data.data()),
                static_cast<std::streamsize>(data.size()));
    f.close();
    if (!f)
        throw std::runtime_error("파일 쓰기 실패: " + path);
    if (restrict_perms && chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) // 0600
        throw std::runtime_error("chmod(0600) 실패: " + path);
}

Bytes read_bytes_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        throw std::runtime_error("파일 열기 실패: " + path);
    std::streamsize n = f.tellg();
    if (n < 0)
        throw std::runtime_error("파일 크기 확인 실패: " + path);
    f.seekg(0);
    Bytes data(static_cast<size_t>(n));
    if (n > 0 && !f.read(reinterpret_cast<char *>(data.data()), n))
        throw std::runtime_error("파일 읽기 실패: " + path);
    return data;
}

void generate_identity_files(const std::string &prefix) {
    MlDsa dsa;
    KeyPair kp = dsa.keypair();
    write_bytes_file(prefix + ".pub", kp.public_key, false);
    write_bytes_file(prefix + ".key", kp.secret_key, true); // 개인키는 0600
}

Identity load_identity(const std::string &my_pub_path, const std::string &my_key_path,
                       const std::string &peer_pub_path) {
    MlDsa dsa;
    Identity id;
    id.sig_public = read_bytes_file(my_pub_path);
    id.sig_secret = read_bytes_file(my_key_path);
    id.peer_sig_public = read_bytes_file(peer_pub_path);
    if (id.sig_public.size() != dsa.public_key_len() ||
        id.sig_secret.size() != dsa.secret_key_len() ||
        id.peer_sig_public.size() != dsa.public_key_len())
        throw std::runtime_error("신원 키 길이 불일치 (파일 손상 또는 알고리즘 불일치)");
    return id;
}

} // namespace pqsec
