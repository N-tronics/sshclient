#include <NetworkServer.hpp>
#include <errno.h>

void NetworkServer::acceptLoop() {
    while (running) {
         struct sockaddr_storage clientAddr;
         socklen_t sin_size = sizeof(clientAddr);

        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 100) <= 0)    // 100ms timeout
            continue;

        int clientSocket = accept(sockfd, (struct sockaddr*)&clientAddr, &sin_size);
        if (clientSocket == -1)
            continue;

        char clientIP[INET6_ADDRSTRLEN];
        inet_ntop(clientAddr.ss_family, utils.get_in_addr((struct sockaddr*)&clientAddr), clientIP, sizeof(clientIP));
        std::string clientAddress = clientIP;
        std::cout << "\nClient @ " << clientAddress << " connected." << std::endl;
        
        auto session = std::make_shared<ClientSession>(clientSocket, clientAddress, serverProtocol);
        clientSessions[clientSocket] = session;

        if (exchangeProtocols(*session) != ErrorCode::SUCCESS) {
            std::cout << "Protocol Exchange FAILED!" << std::endl << std::endl;
            session->disconnect();
            clientSessions.erase(clientSocket);
            continue;
        }

        std::thread clientThread(&NetworkServer::handleClient, this, clientSocket);
        clientThread.detach();
    }
}

void NetworkServer::handleClient(int clientSocket) {
    auto it = clientSessions.find(clientSocket);
    if (it == clientSessions.end())
        return;

    auto& session = *(it->second);
    
    if (clientHandler)
        clientHandler(session);
    
    std::cout << std::endl;
    session.disconnect();
    clientSessions.erase(clientSocket);
}

ErrorCode NetworkServer::exchangeProtocols(ClientSession& session) {
    char buf[NetUtils::MAX_PROTOCOL_LENGTH];
    std::memset(buf, 0, sizeof(buf));
    int bytesRead;
    if ((bytesRead = recv(session.getSocket(), buf, sizeof(buf) - 1, 0)) <= 0) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::string clientProtocol(buf);
    if (clientProtocol.find("\r\n") == std::string::npos) {
        return ErrorCode::PROTOCOL_ERROR;
    }

    session.setClientProtocol(clientProtocol.substr(0, clientProtocol.size() - 2));
    std::cout << "Recvd client protocol: '" << session.getClientProtocol() << "'" << std::endl;

    std::string protocolStr = serverProtocol + "\r\n";
    size_t bytesSent = send(session.getSocket(), protocolStr.c_str(), protocolStr.length(), 0);
    if (bytesSent < 0 | bytesSent < protocolStr.length()) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Sent server protocol: '" << serverProtocol << "'" << std::endl;
    
    return ErrorCode::SUCCESS;
}

NetworkServer::~NetworkServer() { stop(); }

ErrorCode NetworkServer::start(uint16_t _port, const std::string& _bindAddress) {
    if (running)
        return ErrorCode::SUCCESS;
    std::cout << "Server starting..." << std::endl;

    int yes = 1, rv;
    struct addrinfo hints, *servInfo, *p;

    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(_bindAddress.c_str(), std::to_string(_port).c_str(), &hints, &servInfo)) != 0) {
        std::cout << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }

    for (p = servInfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }
    freeaddrinfo(servInfo);
    
    if (p == NULL) {
        std::cout << "Server failed to bind" << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }

    if (listen(sockfd, SERVER_BACKLOG) == -1) {
        close(sockfd);
        sockfd = -1;
        std::cout << "Server failed to listen" << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }
    
    sockStatus = SocketStatus::CONNECTED;
    port = _port;
    bindAddress = _bindAddress;
    std::cout << "Server started on " << bindAddress << " on port: " << port << std::endl;

    running = true;
    acceptThread = std::thread(&NetworkServer::acceptLoop, this);

    return ErrorCode::SUCCESS;
}

void NetworkServer::stop() {
    if (!running) return;

    running = false;
    
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }

    if (acceptThread.joinable())
        acceptThread.join();

    for (auto& session : clientSessions)
        session.second->disconnect();
    clientSessions.clear();

    sockStatus = SocketStatus::DISCONNECTED;
    std::cout << "Server stopped." << std::endl;
}

void NetworkServer::setClientHandler(ClientHandler handler) { clientHandler = handler; }

void NetworkServer::setServerProtocol(const std::string& protocol) { serverProtocol = protocol; }

SocketStatus NetworkServer::getStatus() const { return sockStatus; }

uint16_t NetworkServer::getPort() const { return port; }

const std::string& NetworkServer::getBindAddress() const { return bindAddress; }

size_t NetworkServer::getClientCount() const { return clientSessions.size(); }
