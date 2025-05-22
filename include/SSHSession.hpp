#pragma once

#include <ClientSession.hpp>
#include <Crypto.hpp>
#include <TypeDefs.hpp>
#include <TCPPacket.hpp>
#include <SSHUtils.hpp>
#include <SocketUtils.hpp>

namespace ssh {

class SSHSession : public ClientSession {
private:
    bool encryptionEnabled;
    Bytes sessionID;
    Bytes encryptionKey;
    Bytes encryptionIV;
    Bytes integrityKey;
    std::unique_ptr<crypto::AES256CBC> aes;
public:
    SSHUtils sshUtils;
    SSHSession(const ClientSession& clientSession);
    ~SSHSession();
    
    void setSessionID(const Bytes& _sessionID);
    void enableEncryption();
    const Bytes& getSessionID() const;
};

} // namespace ssh

