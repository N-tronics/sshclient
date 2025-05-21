#include <ClientSession.hpp>

ClientSession::ClientSession(int _sockfd, const std::string& _clientAddress, const std::string& _serverProtocol) {
    sockfd = _sockfd;
    clientAddress = _clientAddress;
    serverProtocol = _serverProtocol;
    utils = NetUtils(_sockfd);
}
ClientSession::~ClientSession() {
    disconnect();
}
void ClientSession::disconnect() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    sockStatus = SocketStatus::DISCONNECTED;
}

int ClientSession::getSocket() const { return sockfd; }
const std::string& ClientSession::getClientAddress() const { return clientAddress; }
SocketStatus ClientSession::getSockStatus() const { return sockStatus; }
const std::string& ClientSession::getClientProtocol() const { return clientProtocol; }
void ClientSession::setClientProtocol(const std::string& protocol) { clientProtocol = protocol; }
