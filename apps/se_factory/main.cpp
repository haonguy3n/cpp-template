// se_factory: factory provisioning CLI for the NXP SE05x secure element.
//
// SCP03 keys are hardcoded in se_connection.cpp (kDefaultKeys).
// Use --port to override the connection string (default: EX_SSS_BOOT_SSS_PORT).

#include <etlx/conf/cli.hpp>
#include <etlx/se/connection.hpp>
#include <etlx/se/object_store.hpp>
#include <etlx/se/rsa_key.hpp>
#include <etlx/se/scp03.hpp>
#include <etlx/log/log.hpp>
#include "host/host_io.hpp"

#include <cstdio>
#include <cstring>

using namespace etlx;
using namespace etlx::se;
namespace conf = etlx::conf;

static const conf::CliApp& App() {
    static const conf::CliApp app = [] {
        conf::CliApp a;
        a.name              = "se_factory";
        a.short_description = "Factory provisioning CLI for the NXP SE05x";
        a.long_description  = "Global: --port <addr>  (default: EX_SSS_BOOT_SSS_PORT)";

        {
            conf::CliCommand cmd;
            cmd.name        = "provision";
            cmd.description = "Generate RSA key + print CSR PEM";
            cmd.options.push_back({"--bits",    "Key size: 2048 (default) or 4096", "BITS"});
            cmd.options.push_back({"--policy",  "full | sign-only | sign-decrypt",  "POLICY"});
            cmd.options.push_back({"--subject", "Subject DN for the CSR",           "DN"});
            cmd.options.push_back({"--out",     "Write CSR PEM to file (default: stdout)", "FILE"});
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "write-cert";
            cmd.description = "Write DER cert to SE cert object";
            cmd.argument    = conf::CliArgument{"cert.der", true};
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "write-info";
            cmd.description = "Write binary blob to SE device-info object";
            cmd.argument    = conf::CliArgument{"blob.bin", true};
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "read-info";
            cmd.description = "Hex-dump the device-info object";
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "rotate-scp03";
            cmd.description = "Rotate SCP03 keys via GP PUT KEY";
            cmd.argument    = conf::CliArgument{"newkeys.txt", true};
            cmd.options.push_back({"--dry-run", "Build APDU but do not send", ""});
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "uid";
            cmd.description = "Print the 18-byte chip UID";
            a.commands.push_back(cmd);
        }
        {
            conf::CliCommand cmd;
            cmd.name        = "verify";
            cmd.description = "Verify SE key matches a DER certificate";
            cmd.argument    = conf::CliArgument{"cert.der", true};
            a.commands.push_back(cmd);
        }

        return a;
    }();
    return app;
}

static size_t ReadFile(const char *path, uint8_t *buf, size_t capacity) {
    FILE *fp = std::fopen(path, "rb");
    if (!fp) { ETLX_LOG_ERROR("se_factory: cannot open '%s'", path); return 0; }
    size_t n = std::fread(buf, 1, capacity, fp);
    std::fclose(fp);
    return n;
}

static int CmdProvision(Connection &conn, const conf::CliCommand &cmd,
                        int argc, char **argv) {
    RsaBits bits = RsaBits::k2048;
    KeyPolicy policy = KeyPolicy::Full;  // match se05x cpp_app: default policy is Full (deletable)
    const char *subject_dn = "CN=SE05x-Device";
    const char *out_path = nullptr;

    conf::CmdlineOptionsIterator it(argc, argv, cmd);
    for (;;) {
        auto next = it.Next();
        if (!next) {
            ETLX_LOG_ERROR("provision: %s", next.error().message.c_str());
            return 1;
        }
        if (!next.value()) break;
        const auto &ov = next.value().value();
        if (ov.option == "--bits") {
            if (ov.value == "4096") bits = RsaBits::k4096;
        } else if (ov.option == "--policy") {
            if      (ov.value == "full")         policy = KeyPolicy::Full;
            else if (ov.value == "sign-decrypt") policy = KeyPolicy::SignDecrypt;
        } else if (ov.option == "--subject") {
            subject_dn = ov.value.data(); // argv-backed, null-terminated
        } else if (ov.option == "--out") {
            out_path = ov.value.data(); // argv-backed, null-terminated
        }
    }

    ObjectStore store(conn);
    if (store.Exists(kRsaKeyId)) {
        ETLX_LOG_INFO("provision: key 0x%08x exists, erasing before regenerate",
                      static_cast<unsigned>(kRsaKeyId));
        auto er = store.Erase(kRsaKeyId);
        if (!er) { ETLX_LOG_ERROR("provision: erase: %s", er.error().message.c_str()); return 1; }
    }

    auto key_res = RsaKey::Generate(conn, kRsaKeyId, bits, policy);
    if (!key_res) { ETLX_LOG_ERROR("provision: %s", key_res.error().message.c_str()); return 1; }
    auto csr_res = key_res.value().MakeCsr(subject_dn);
    if (!csr_res) { ETLX_LOG_ERROR("provision: CSR: %s", csr_res.error().message.c_str()); return 1; }
    const auto &csr = csr_res.value();
    if (out_path) {
        FILE *fp = std::fopen(out_path, "wb");
        if (!fp) { ETLX_LOG_ERROR("provision: cannot open '%s' for writing", out_path); return 1; }
        size_t n = std::fwrite(csr.c_str(), 1, csr.size(), fp);
        bool ok = (n == csr.size());
        if (std::fclose(fp) != 0) ok = false;
        if (!ok) { ETLX_LOG_ERROR("provision: failed writing CSR to '%s'", out_path); return 1; }
        ETLX_LOG_INFO("provision: CSR written to %s (%zu bytes)", out_path, csr.size());
    } else {
        std::fputs(csr.c_str(), stdout);
    }
    return 0;
}

static int CmdWriteCert(Connection &conn, const char *path) {
    static uint8_t buf[ETLX_SE_CERT_CAPACITY];
    size_t n = ReadFile(path, buf, sizeof(buf));
    if (n == 0) return 1;
    ObjectStore store(conn);
    auto st = store.WriteCert(kRsaCertId, buf, n);
    if (!st) { ETLX_LOG_ERROR("write-cert: %s", st.error().message.c_str()); return 1; }
    ETLX_LOG_INFO("se_factory: cert written (%zu bytes)", n);
    return 0;
}

static int CmdWriteInfo(Connection &conn, const char *path) {
    static uint8_t buf[ETLX_SE_BLOB_CAPACITY];
    size_t n = ReadFile(path, buf, sizeof(buf));
    if (n == 0) return 1;
    ObjectStore store(conn);
    auto res = store.WriteBinary(kDeviceInfoId, buf, n, /*force=*/true);
    if (!res) { ETLX_LOG_ERROR("write-info: %s", res.error().message.c_str()); return 1; }
    ETLX_LOG_INFO("se_factory: info blob written (%zu bytes)", n);
    return 0;
}

static int CmdReadInfo(Connection &conn) {
    ObjectStore store(conn);
    auto res = store.ReadBinary(kDeviceInfoId);
    if (!res) { ETLX_LOG_ERROR("read-info: %s", res.error().message.c_str()); return 1; }
    const auto &blob = res.value();
    for (size_t i = 0; i < blob.size(); ++i) {
        if (i && i % 16 == 0) std::putchar('\n');
        std::printf("%02x ", blob[i]);
    }
    std::putchar('\n');
    return 0;
}

static int CmdRotateScp03(const char *port, const conf::CliCommand &cmd,
                          int argc, char **argv) {
    const char *keyfile = nullptr;
    bool dry_run = false;

    conf::CmdlineOptionsIterator it(argc, argv, cmd);
    for (;;) {
        auto next = it.Next();
        if (!next) {
            ETLX_LOG_ERROR("rotate-scp03: %s", next.error().message.c_str());
            return 1;
        }
        if (!next.value()) break;
        const auto &ov = next.value().value();
        if (ov.is_argument)         keyfile  = ov.value.data();
        else if (ov.option == "--dry-run") dry_run = true;
    }
    if (!keyfile) {
        ETLX_LOG_ERROR("rotate-scp03: missing <newkeys.txt> argument");
        return 1;
    }

    auto conn_res = Connection::Open(port, /*select_applet=*/false);
    if (!conn_res) {
        ETLX_LOG_ERROR("rotate-scp03: open: %s", conn_res.error().message.c_str());
        return 1;
    }
    Scp03Admin admin(std::move(conn_res.value()));
    auto new_keys_res = scp03_keyfile::Read(keyfile);
    if (!new_keys_res) {
        ETLX_LOG_ERROR("rotate-scp03: %s", new_keys_res.error().message.c_str());
        return 1;
    }
    auto st = admin.Rotate(new_keys_res.value(), dry_run, dry_run ? nullptr : keyfile);
    if (!st) { ETLX_LOG_ERROR("rotate-scp03: %s", st.error().message.c_str()); return 1; }
    return 0;
}

static int CmdUid(Connection &conn) {
    ObjectStore store(conn);
    auto res = store.GetUid();
    if (!res) { ETLX_LOG_ERROR("uid: %s", res.error().message.c_str()); return 1; }
    for (size_t i = 0; i < ETLX_SE_UID_LEN; ++i)
        std::printf("%02x", res.value()[i]);
    std::putchar('\n');
    return 0;
}

static int CmdVerify(Connection &conn, const char *cert_path) {
    static uint8_t buf[ETLX_SE_CERT_CAPACITY];
    size_t n = ReadFile(cert_path, buf, sizeof(buf));
    if (n == 0) return 1;
    ObjectStore store(conn);
    auto res = store.VerifyBinding(kRsaKeyId, buf, n);
    if (!res) { ETLX_LOG_ERROR("verify: %s", res.error().message.c_str()); return 1; }
    std::puts(res.value() ? "BINDING OK" : "BINDING FAIL");
    return res.value() ? 0 : 2;
}

int main(int argc, char **argv) {
    static ports::host::StderrLogSink log_sink;
    log::SetSink(&log_sink);
    log::SetLevel(log::Level::Info);

    ports::host::FileWriter out; // stdout

    // Consume global --port flag before the command name.
    const char *port = "/dev/i2c-3";
    int argi = 1;
    while (argi < argc && std::strncmp(argv[argi], "--", 2) == 0) {
        if (std::strcmp(argv[argi], "--port") == 0 && argi + 1 < argc)
            port = argv[++argi];
        ++argi;
    }

    if (argi >= argc || etl::string_view{argv[argi]} == "--help" ||
        etl::string_view{argv[argi]} == "-h" || etl::string_view{argv[argi]} == "help") {
        conf::PrintCliHelp(App(), out);
        return 0;
    }

    const etl::string_view cmd_name{argv[argi++]};
    const conf::CliCommand *cmd = conf::FindCommand(App(), cmd_name);
    if (!cmd) {
        ETLX_LOG_ERROR("se_factory: unknown command '%.*s'",
                       static_cast<int>(cmd_name.size()), cmd_name.data());
        conf::PrintCliHelp(App(), out);
        return 1;
    }

    // Per-command help ("<cmd> -h|--help") prints usage without touching the SE.
    for (int j = argi; j < argc; ++j) {
        const etl::string_view a{argv[j]};
        if (a == "-h" || a == "--help") {
            conf::PrintCliCommandHelp(App(), cmd_name, out);
            return 0;
        }
    }

    // rotate-scp03 opens its own ISD session (select_applet=false).
    if (cmd_name == "rotate-scp03")
        return CmdRotateScp03(port, *cmd, argc - argi, argv + argi);

    // All other commands share one normal (applet-selected) session.
    auto conn_res = Connection::Open(port);
    if (!conn_res) {
        ETLX_LOG_ERROR("se_factory: %s", conn_res.error().message.c_str());
        return 1;
    }
    Connection &conn = conn_res.value();

    if (cmd_name == "provision")
        return CmdProvision(conn, *cmd, argc - argi, argv + argi);

    // Commands with a single mandatory positional argument.
    const char *path = nullptr;
    if (cmd->argument) {
        if (argi > argc - 1) {
            ETLX_LOG_ERROR("se_factory: %.*s: missing <%.*s> argument",
                           static_cast<int>(cmd_name.size()), cmd_name.data(),
                           static_cast<int>(cmd->argument.value().name.size()),
                           cmd->argument.value().name.data());
            conf::PrintCliCommandHelp(App(), cmd_name, out);
            return 1;
        }
        path = argv[argi];
    }

    if (cmd_name == "write-cert") return CmdWriteCert(conn, path);
    if (cmd_name == "write-info") return CmdWriteInfo(conn, path);
    if (cmd_name == "read-info")  return CmdReadInfo(conn);
    if (cmd_name == "uid")        return CmdUid(conn);
    if (cmd_name == "verify")     return CmdVerify(conn, path);

    return 1; // unreachable
}
