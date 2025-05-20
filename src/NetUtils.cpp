#include <NetUtils.hpp>

bool NetUtils::recvBytes(Bytes& bytes, size_t length, uint32_t timeout_ms) const {
    size_t bytesRead = 0;
    bytes.reserve(length);
    while (bytesRead < length) {
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeout_ms) <= 0)
            return false;

        size_t res;
        if (recv(sockfd, bytes.data() + bytesRead, length - bytesRead, 0) <= 0)
            return false;
        bytesRead += res;
    }
    return true;
}

ErrorCode NetUtils::sendTCPPacket(const TCPPacket& packet) const {
    Bytes data = packet.serialize();

    size_t bytesSent = send(sockfd, data.data(), data.size(), 0);
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
    if (packetLength > TCPPacket::MAX_TCP_PACKET_SIZE)
        return ErrorCode::PROTOCOL_ERROR;
    
    Bytes packetData(4 + packetLength), packetPayload;
    packetData.insert(packetData.end(), lengthBuffer.begin(), lengthBuffer.end());
    if (!recvBytes(packetPayload, packetLength, timeout_ms))
        return ErrorCode::TIMEOUT;
    packetData.insert(packetData.end(), packetPayload.begin(), packetPayload.end());

    try {
        packet.deserialize(packetData);
    } catch (const std::exception& e) {
        return ErrorCode::PROTOCOL_ERROR;
    }

    return ErrorCode::SUCCESS;
}

