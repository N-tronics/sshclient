#include <ClientSession.hpp>

ClientSession::ClientSession(int _sockfd, const std::string& _clientAddress, const std::string& _serverProtocol) {
    sockfd = std::make_shared<int>(_sockfd);
    sockStatus = std::make_shared<SocketStatus>(SocketStatus::CONNECTED);
    clientAddress = _clientAddress;
    serverProtocol = _serverProtocol;
    utils.setSockfd(sockfd);
}

ClientSession::~ClientSession() {
    disconnect();
}

void ClientSession::disconnect() {
    if (sockfd && *sockfd >= 0) {
        close(*sockfd);
        *sockfd = -1;
    }
    sockfd.reset();
    *sockStatus = SocketStatus::DISCONNECTED;
}

const std::shared_ptr<int> ClientSession::getSockfd() const { return sockfd; }
const std::shared_ptr<SocketStatus> ClientSession::getSockStatus() const { return sockStatus; }
void ClientSession::setSockStatus(SocketStatus _sockStatus) { *sockStatus = _sockStatus; }
const std::string& ClientSession::getClientAddress() const { return clientAddress; }
const std::string& ClientSession::getClientProtocol() const { return clientProtocol; }
const std::string& ClientSession::getServerProtocol() const { return serverProtocol; }
void ClientSession::setClientProtocol(const std::string& protocol) { clientProtocol = protocol; }
