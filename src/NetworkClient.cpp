#include <NetworkClient.hpp>

ErrorCode NetworkClient::exchangeProtocols() {
    
    std::string protocolStr = clientProtocol + "\r\n";
    std::cout << protocolStr << std::endl;
    size_t bytesSent = send(sockfd, protocolStr.c_str(), protocolStr.length(), 0);
    if (bytesSent < 0 | bytesSent < protocolStr.length())
        return ErrorCode::PROTOCOL_ERROR;
    std::cout << "Sent client protocol: '" << clientProtocol << "'" << std::endl;
    
    
    char buf[NetUtils::MAX_PROTOCOL_LENGTH];
    std::memset(buf, 0, sizeof(buf));
    int bytesRead;
    if ((bytesRead = recv(sockfd, buf, sizeof(buf) - 1, 0)) <= 0) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::string _serverProtocol(buf);
    if (_serverProtocol.find("\r\n") == std::string::npos) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    serverProtocol = _serverProtocol.substr(0, _serverProtocol.size() - 2);
    std::cout << "Recvd server protocol: '" << serverProtocol << "'" << std::endl;
    return ErrorCode::SUCCESS;
}

NetworkClient::~NetworkClient() {
    disconnect();
}

ErrorCode NetworkClient::connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms) {
    int rv;
    struct addrinfo hints, *servInfo, *p;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char s[INET6_ADDRSTRLEN];
    std::cout << _hostName << std::endl;

    if ((rv = getaddrinfo(_hostName.c_str(), std::to_string(_port).c_str(), &hints, &servInfo)) != 0) {
        std::cout << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }
    
    int flags;
    for (p = servInfo; p != NULL; p = p->ai_next) {
        inet_ntop(p->ai_family, utils.get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof(s));
        std::cout << "Connecting to " << s << std::endl;
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        // set socket to be non-blocking TODO
        // flags = fcntl(sockfd, F_GETFL, 0);
        // fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            std::cout << "couldnt connect" << std::endl;
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
    // fcntl(sockfd, F_SETFL, flags);
    freeaddrinfo(servInfo);

    sockStatus = SocketStatus::CONNECTED;
    hostName = _hostName;
    port = _port;
    utils = NetUtils(sockfd);

    ErrorCode res = exchangeProtocols();
    if (res != ErrorCode::SUCCESS) {
        std::cout << "Exchange protocols failed" << std::endl;
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

void NetworkClient::setClientProtocol(const std::string& protocol) { clientProtocol = protocol; }
SocketStatus NetworkClient::getStatus() const { return sockStatus; }
uint16_t NetworkClient::getPort() const { return port; }
const std::string& NetworkClient::getHostName() const { return hostName; }
const std::string& NetworkClient::getServerProtocol() const { return serverProtocol; }
