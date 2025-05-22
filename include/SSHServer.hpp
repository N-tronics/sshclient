#pragma once

#include <TypeDefs.hpp>
#include <SocketUtils.hpp>
#include <NetworkServer.hpp>
#include <SSHSession.hpp>
#include <Crypto.hpp>

namespace ssh {

class SSHServer: public NetworkServer {
private:
    crypto::rsa::RSA rsa;
    Bytes serverRSAPublicKeyBytes;
    
    void handleClientConnection(ClientSession& session);
    ErrorCode performKEX(SSHSession& session);
public:
    using SSHClientHandler = std::function<void(SSHSession&)>;

    SSHClientHandler sshClientHandler;
    static constexpr uint16_t SSH_DEFAULT_PORT = 22;

    SSHServer() : NetworkServer() {}
    ~SSHServer();

    ErrorCode startSSH(uint16_t _port = SSH_DEFAULT_PORT, const std::string& _bindAddress = "127.0.0.1");
    void setSSHClientHandler(SSHClientHandler handler);
};

} // namespace ssh
