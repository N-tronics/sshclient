#pragma once

#include <TypeDefs.hpp>
#include <TCPPacket.hpp>
#include <NetUtils.hpp>
#include <SocketUtils.hpp>

class ClientSession {
protected:
    std::shared_ptr<int> sockfd;
    std::shared_ptr<SocketStatus> sockStatus;
    std::string clientAddress;
    std::string clientProtocol;
    std::string serverProtocol;

public:
    NetUtils utils;
    ClientSession(int _sockfd, const std::string& _clientAddress, const std::string& _serverProtocol);
    ClientSession() {}
    ~ClientSession();

    void disconnect();
    const std::shared_ptr<int> getSockfd() const;
    const std::shared_ptr<SocketStatus> getSockStatus() const;
    void setSockStatus(SocketStatus _sockStatus);
    const std::string& getClientAddress() const;
    const std::string& getClientProtocol() const;
    const std::string& getServerProtocol() const;
    void setClientProtocol(const std::string& protocol);
};

