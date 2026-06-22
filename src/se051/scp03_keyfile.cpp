#include <se051/scp03.hpp>

#include <cstdio>
#include <cstring>

namespace se051::scp03_keyfile {

namespace {

bool Parse16(const char *p, uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) {
        unsigned b = 0;
        if (std::sscanf(p + i * 2, "%02x", &b) != 1) // NOLINT
            return false;
        out[i] = static_cast<uint8_t>(b);
    }
    return true;
}

bool FindKey(const char *path, const char *tag, uint8_t out[16]) {
    FILE *fp = std::fopen(path, "r");
    if (!fp) return false;
    char line[256];
    bool found = false;
    const size_t tag_len = std::strlen(tag);
    while (std::fgets(line, sizeof(line), fp)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (std::strncmp(p, tag, tag_len) != 0 || p[tag_len] != ' ') continue;
        p += tag_len + 1;
        while (*p == ' ' || *p == '\t') ++p;
        found = Parse16(p, out);
        break;
    }
    std::fclose(fp);
    return found;
}

} // namespace

Status ReadDek(const char *path, uint8_t dek[16]) {
    if (!FindKey(path, "DEK", dek))
        return SeFail(kReadFailed, "SCP03 key file: DEK line missing or malformed");
    return Ok();
}

Result<Scp03KeySet> Read(const char *path) {
    Scp03KeySet ks{};
    if (!FindKey(path, "ENC", ks.enc) || !FindKey(path, "MAC", ks.mac) ||
        !FindKey(path, "DEK", ks.dek))
        return SeFail(kReadFailed, "SCP03 key file: missing or malformed ENC/MAC/DEK line");
    return ks;
}

Status Write(const char *path, const Scp03KeySet &keys) {
    // Build tmp path.
    char tmp[256];
    if (std::snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= static_cast<int>(sizeof(tmp)))
        return SeFail(kWriteFailed, "scp03_keyfile: path too long");

    FILE *fp = std::fopen(tmp, "w");
    if (!fp)
        return SeFail(kWriteFailed, "scp03_keyfile: cannot open tmp file for writing");

    auto write_key = [&](const char *tag, const uint8_t *k) -> bool {
        if (std::fprintf(fp, "%s ", tag) < 0) return false;
        for (int i = 0; i < 16; ++i)
            if (std::fprintf(fp, "%02x", k[i]) < 0) return false;
        return std::fprintf(fp, "\n") >= 0;
    };

    bool ok = write_key("ENC", keys.enc) && write_key("MAC", keys.mac) &&
              write_key("DEK", keys.dek);
    std::fclose(fp);

    if (!ok) {
        std::remove(tmp);
        return SeFail(kWriteFailed, "scp03_keyfile: write error");
    }

    // Back up existing key file.
    char bak[256];
    if (std::snprintf(bak, sizeof(bak), "%s.bak", path) < static_cast<int>(sizeof(bak))) {
        std::remove(bak);
        std::rename(path, bak); // best-effort; ignore failure
    }

    if (std::rename(tmp, path) != 0) {
        std::remove(tmp);
        return SeFail(kWriteFailed, "scp03_keyfile: rename tmp -> path failed");
    }
    return Ok();
}

} // namespace se051::scp03_keyfile
