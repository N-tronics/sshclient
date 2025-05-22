#pragma once

#include <NetworkClient.hpp>
#include <SSHPacket.hpp>
#include <SSHUtils.hpp>
#include <NetUtils.hpp>
#include <Crypto.hpp>
#include <TypeDefs.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace ssh {

class SSHClient: public NetworkClient {
private:
    bool kexComplete;
    bool encryptionEnabled;
    
    Bytes clientKexInit;
    Bytes serverKexInit;
    Bytes sessionId;

    ErrorCode performKEX();
public:
    SSHUtils sshUtils;
    SSHClient() : 
        kexComplete(false),
        encryptionEnabled(false) 
    {}
    
    ErrorCode connectTo(const std::string& hostname, uint16_t port = SSH_DEFAULT_PORT, uint32_t timeout_ms = 5000) override;
};

}; // namespace ssh
