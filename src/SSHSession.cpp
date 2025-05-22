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

void SSHSession::setSessionID(const Bytes& _sessionID) { sessionID = _sessionID; }

void SSHSession::enableEncryption() { encryptionEnabled = true; }

const Bytes& SSHSession::getSessionID() const { return sessionID; }

} // namespace ssh
