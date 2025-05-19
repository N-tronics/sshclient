#include <NetworkClient.hpp>

ErrorCode NetworkClient::exchangeProtocolVersions() {
    std::string protocolStr = protocol + "\r\n";
    size_t bytesSent = send(sockfd, protocolStr.c_str(), protocolStr.length(), 0);
    if (bytesSent < 0 | bytesSent < protocolStr.length())
        return ErrorCode::PROTOCOL_ERROR;

    char buf[MAX_PROTOCOL_LENGTH];
    std::memset(buf, 0, sizeof(buf));

    size_t bytesRead = 0, res;
    bool crlfFound = false;
    while (bytesRead < sizeof(buf) - 1 && !crlfFound) {
        if ((res = recv(sockfd, buf + bytesRead, 1, 0) <= 0)
            return ErrorCode::PROTOCOL_ERROR;
        bytesRead++;

        if (bytesRead > 0 && buf[bytesRead - 2] == '\r' && buf[bytesRead - 1] == '\n')
            crlfFound = true;
    }
    if (!crlfFound)
        return ErrorCode::PROTOCOL_ERROR;
    buf[bytesRead] = 0;

    serverProtocol = std::string(buf, bytesRead - 2);
    return ErrorCode::SUCCESS;
}

bool NetworkClient::recvBytes(Bytes& bytes, size_t length, uint32_t timeout_ms) {
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

ErrorCode NetworkClient::connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms = 5000) {
    int rv;
    struct addrinfo hints, *servInfo, *p;

    std::memset(&hints, 0, sizeof(hints));
    hint.ai_family = AF_UNSPEC;
    hitn.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(_hostName, _port), &hints, &servInfo)) != 0) {
        std::cout << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }
    
    int flags;
    for (p = servInfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        // set socket to be non-blocking
        flags = fcntl(m_socket, F_GETFL, 0);
        fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);
        
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }
    if (p == NULL) {
        std::cout << "Failed to connect to host" << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }
    // Set socket back to blocking mode
    fcntl(m_socket, F_SETFL, flags);
    freeaddrinfo(servInfo);

    sockStatus = SocketStatus::CONNECTED;
    hostName = _hostName;
    port = _port;

    ErrorCode res = exchangeProtocols();
    if (!success(res)) {
        disconnect();
        return res;
    }

    return ErrorCode::SUCCESS;
}

void NetworkClient::disconnect() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    sockStatus = SocketStatus::DISCONNECTED;
    hostName.clear();
    port = 0;
}

ErrorCode NetworkClient::sendTCPPacket(const TCPPacket& packet) const {
    if (sockStatus != SocketStatus::CONNECTED)
        return ErrorCode::CONNECTION_FAILED;

    Bytes data = packet.serialize();

    size_t bytesSent = send(sockfd, data.data(), data.size(), 0);
    if (bytesSent < 0 || bytesSent != data.size())
        return ErrorCode::PROTOCOL_ERROR;

    return ErrorCode::SUCCESS;
}

ErrorCode NetworkClient::recvTCPPacket(TCPPacket& packet, uint32_t timeout_ms = 5000) const {
    if (sockStatus != SocketStatus::CONNECTED)
        return ErrorCode::CONNECTION_FAILED;
    
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
    if (!recvBytes(packetData.data() + 4, packetLength, timeout_ms))
        return ErrorCode::TIMEOUT;

    try {
        packet.deserialize(packetData);
    } catch (const std::exception& e) {
        return ErrorCode::PROTOCOL_ERROR;
    }

    return ErrorCode::SUCCESS;
}

SocketStatus NetworkClient::getStatus() const { return sockStatus; }
uint16_t NetworkClient::getPort() const { return port; }
const std::string& NetworkClient::getHostName() const { return hostName; }
const std::string& NetworkClient::getServerProtocol() const { return serverProtocol; }
