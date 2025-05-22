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

// Socket status
enum class SocketStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
};

class NetUtils {
protected:
    std::shared_ptr<int> sockfd;
public:
    static constexpr uint32_t MAX_PROTOCOL_LENGTH = 256;
    
    NetUtils() {}
    
    void setSockfd(const std::shared_ptr<int>& _sockfd);
    const std::shared_ptr<int> getSockfd() const;
    void *get_in_addr(struct sockaddr *sa) const; 
    bool recvBytes(Bytes& bytes, size_t length, uint32_t timeout_ms) const;
    ErrorCode sendTCPPacket(const TCPPacket& packet) const;
    ErrorCode recvTCPPacket(TCPPacket& packet, uint32_t timeout_ms = 5000) const;
};

