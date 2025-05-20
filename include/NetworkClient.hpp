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
    int sockfd;
    SocketStatus sockStatus;
    uint16_t port;
    std::string hostName;
    std::string serverProtocol;
    std::string clientProtocol;
    NetUtils utils;

    ErrorCode exchangeProtocols();
public:
    static constexpr uint32_t MAX_PROTOCOL_LENGTH = 256;
    
    NetworkClient() : sockfd(-1), sockStatus(SocketStatus::DISCONNECTED) {}
    ~NetworkClient();

    virtual ErrorCode connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms = 5000);
    void disconnect();

    SocketStatus getStatus() const;
    uint16_t getPort() const;
    const std::string& getHostName() const;
    const std::string& getServerProtocol() const;
};

