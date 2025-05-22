#include <NetUtils.hpp>
#include <cstring>
    
void NetUtils::setSockfd(const std::shared_ptr<int>& _sockfd) {
    if (sockfd)
        sockfd.reset();
    sockfd = _sockfd;
}
    
const std::shared_ptr<int> NetUtils::getSockfd() const { return sockfd; }

void* NetUtils::get_in_addr(struct sockaddr *sa) const {
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

bool NetUtils::recvBytes(Bytes& bytes, size_t length, uint32_t timeout_ms) const {
    if (!sockfd) {
        throw std::runtime_error("Trying to receive bytes on an invalid socket");
        return false;
    }
    
    size_t bytesRead = 0;
    Byte buf[length];
    std::memset(buf, 0, sizeof(buf));
    while (bytesRead < length) {
        struct pollfd pfd;
        pfd.fd = *sockfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeout_ms) <= 0)
            return false;

        size_t res;
        if ((res = recv(*sockfd, buf + bytesRead, length - bytesRead, 0)) <= 0)
            return false;
        bytesRead += res;
    }
    bytes.reserve(length);
    bytes.insert(bytes.begin(), buf, buf + bytesRead);
    return true;
}

ErrorCode NetUtils::sendTCPPacket(const TCPPacket& packet) const {
    Bytes data = packet.serialize();
    std::cout << "Packet Data: " << std::endl;
    for (Byte b : data) 
        std::cout << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    std::cout << std::endl << std::dec;

    size_t bytesSent = send(*sockfd, data.data(), data.size(), 0);
    if (bytesSent < 0 || bytesSent != data.size())
        return ErrorCode::PROTOCOL_ERROR;

    return ErrorCode::SUCCESS;
}

ErrorCode NetUtils::recvTCPPacket(TCPPacket& packet, uint32_t timeout_ms) const {
    Bytes lengthBuffer;
    if (!recvBytes(lengthBuffer, 4, timeout_ms))
        return ErrorCode::TIMEOUT;

    uint32_t packetLength = 
        (lengthBuffer[0] << 24) |
        (lengthBuffer[1] << 16) |
        (lengthBuffer[2] <<  8) |
         lengthBuffer[3];
    if (packetLength < 1 || packetLength > TCPPacket::MAX_TCP_PACKET_SIZE)
        return ErrorCode::PROTOCOL_ERROR;
    
    Bytes packetData, packetPayload;
    packetData.insert(packetData.begin(), lengthBuffer.begin(), lengthBuffer.end());
    if (!recvBytes(packetPayload, packetLength, timeout_ms)) {
        return ErrorCode::TIMEOUT;
    }
    packetData.insert(packetData.end(), packetPayload.begin(), packetPayload.end());
    std::cout << "Packet Data: " << std::endl;
    for (Byte b : packetData) 
        std::cout << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    std::cout << std::endl << std::dec;

    try {
        packet.deserialize(packetData);
    } catch (const std::exception& e) {
        return ErrorCode::PROTOCOL_ERROR;
    }

    return ErrorCode::SUCCESS;
}

