#include <SSHSession.hpp>

namespace ssh {

SSHSession::SSHSession(const ClientSession& clientSession) {
    sockfd = clientSession.getSockfd();
    sockStatus = clientSession.getSockStatus();
    clientAddress = clientSession.getClientAddress();
    clientProtocol = clientSession.getClientProtocol();
    serverProtocol =  clientSession.getServerProtocol();
    sshUtils = SSHUtils(clientSession.utils);
}

SSHSession::~SSHSession() {
    disconnect();
}

void SSHSession::enableEncryption() { encryptionEnabled = true; }

} // namespace ssh
