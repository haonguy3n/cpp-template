#pragma once

#include <se051/connection.hpp>

#include <cstdint>

namespace se051 {

// One full set of 128-bit Platform SCP03 static keys (ENC/MAC/DEK).
struct Scp03KeySet {
    uint8_t enc[16];
    uint8_t mac[16];
    uint8_t dek[16];
};

// The compiled-in default Platform SCP03 key set that Connection::Open uses to
// authenticate.  Exposed so callers can rotate away from / back to it.
const Scp03KeySet &DefaultScp03Keys();

// Key file: read/write the three 128-bit SCP03 keys from/to a text file.
// Format (one key per line, space-separated tag + 32 lowercase hex digits):
//   ENC 00112233...
//   MAC 00112233...
//   DEK 00112233...
namespace scp03_keyfile {

// Read all three keys from path.  Returns error if any key line is missing or
// malformed.
Result<Scp03KeySet> Read(const char *path);

// Read just the DEK (the rotation flow wraps new keys with it).
Status ReadDek(const char *path, uint8_t dek[16]);

// Atomically write keys to path: rename existing to <path>.bak, write a tmp
// file, then rename tmp → path so a crash never corrupts the key file.
Status Write(const char *path, const Scp03KeySet &keys);

} // namespace scp03_keyfile

// One-call Platform SCP03 key rotation entry point.  Owns a dedicated ISD
// session (applet not selected) and runs GP PUT KEY over it.
//
// The rotation is IRREVERSIBLE: after success the SE only accepts the new keys.
// The current session continues until closed but the NEXT session must use the
// new keys.  Always persist the new key set (via Scp03Admin::Rotate with a
// key_file path) before closing the current session.
class Scp03Admin {
public:
    // Construct from an ISD connection: Connection::Open(port, /*select_applet=*/false).
    explicit Scp03Admin(Connection &&c) : conn_(std::move(c)) {}

    // Install newKeys.  If key_file is non-null and dry_run is false, atomically
    // writes the new key set to the file on success.
    Status Rotate(const Scp03KeySet &new_keys, bool dry_run, const char *key_file = nullptr);

    // File-free rotation for in-memory key sets (no key file read or written).
    // current_keys supplies the DEK used to wrap new_keys and must match what
    // the SE currently holds; new_keys is installed.  Because the current
    // session stays valid after a PUT KEY, this may be called repeatedly on one
    // Scp03Admin — e.g. rotate to fresh keys, confirm, then rotate back to the
    // originals.
    Status Rotate(const Scp03KeySet &current_keys, const Scp03KeySet &new_keys,
                  bool dry_run = false);

    Scp03Admin(Scp03Admin &&) = default;
    ~Scp03Admin() = default;
    Scp03Admin(const Scp03Admin &) = delete;
    Scp03Admin &operator=(const Scp03Admin &) = delete;

private:
    Connection conn_;
};

} // namespace se051
