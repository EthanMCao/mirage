#pragma once

#include <memory>
#include <string>

#include "mirage/audit.hpp"

namespace mirage::session {

enum class AuthMode {
    // Harvest credentials, then return an auth-failed error. Most realistic
    // for catching credential-spray bots; the connection drops fast.
    Collect,
    // Harvest credentials, then accept the login and serve canned responses.
    // Lets us see what queries the attacker runs after "logging in."
    Accept,
};

struct Config {
    AuthMode auth_mode = AuthMode::Collect;
    std::string server_version = "16.2";
    std::string fake_pid_secret = "honeypot";
};

// Drives one client connection start to finish: reads the StartupMessage,
// requests cleartext password, harvests it, returns auth-failed or canned
// success based on `cfg.auth_mode`, then loops over Query messages until
// Terminate / EOF / error. Emits audit events at every interesting step.
//
// Closes `fd` before returning. Safe to call from a worker thread.
void run(int fd,
         const std::string& src_ip,
         int src_port,
         const Config& cfg,
         audit::AuditPipeline& pipeline);

}  // namespace mirage::session
