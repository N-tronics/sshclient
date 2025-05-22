#pragma once

#include <TypeDefs.hpp>
#include <TCPPacket.hpp>
#include <NetUtils.hpp>
#include <string>
#include <memory>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <iostream>

class NetworkClient {
protected:
    std::shared_ptr<int> sockfd;
    SocketStatus sockStatus;
    uint16_t port;
    std::string hostName;
    std::string serverProtocol;
    std::string clientProtocol;

    ErrorCode exchangeProtocols();
public:
    NetUtils utils;
    NetworkClient() : sockfd(std::make_shared<int>(0)), sockStatus(SocketStatus::DISCONNECTED) {}
    ~NetworkClient();

    virtual ErrorCode connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms = 5000);
    void disconnect();

    void setClientProtocol(const std::string& protocol);
    SocketStatus getStatus() const;
    uint16_t getPort() const;
    const std::string& getHostName() const;
    const std::string& getServerProtocol() const;
};

