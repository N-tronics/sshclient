#pragma once

#include <TypeDefs.hpp>
#include <TCPPacket.hpp>
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

enum class ErrorCode : int {
    SUCCESS = 0,
    CONNECTION_FAILED = 1,
    AUTHENTICATION_FAILED = 2,
    TIMEOUT = 3,
    PROTOCOL_ERROR = 4,
    ENCRYPTION_ERROR = 5,
    DECRYPTION_ERROR = 6,
    INVALID_KEY = 7,
    CONNECTION_CLOSED = 8,
    GENERIC_ERROR = 255
};

bool success(ErrorCode e);

// Socket status
enum class SocketStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
};

class NetworkClient {
protected:
    int sockfd;
    SocketStatus sockStatus;
    uint16_t port;
    std::string hostName;
    std::string serverProtocol;
    std::string clientProtocol;

    ErrorCode exchangeProtocols();
    bool recvBytes(Bytes& bytes, size_t length, uint32_t timeout_ms) const;
public:
    static constexpr uint32_t MAX_PROTOCOL_LENGTH = 256;
    
    NetworkClient() : sockfd(-1), sockStatus(SocketStatus::DISCONNECTED) {}
    ~NetworkClient();

    virtual ErrorCode connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms = 5000);
    void disconnect();

    ErrorCode sendTCPPacket(const TCPPacket& packet) const;
    ErrorCode recvTCPPacket(TCPPacket& packet, uint32_t timeout_ms = 5000) const;

    SocketStatus getStatus() const;
    uint16_t getPort() const;
    const std::string& getHostName() const;
    const std::string& getServerProtocol() const;
};

