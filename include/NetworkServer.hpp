#pragma once

#include <TypeDefs.hpp>
#include <ClientSession.hpp>
#include <TCPPacket.hpp>
#include <NetUtils.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <atomic>
#include <map>
#include <functional>
#include <thread>

class NetworkServer {
public:
    using ClientHandler = std::function<void(ClientSession&)>;

    static constexpr uint32_t SERVER_BACKLOG = 20;
protected:
    int sockfd;
    SocketStatus sockStatus;
    uint16_t port;
    std::string bindAddress;
    std::string serverProtocol;
    std::atomic<bool> running;
    std::thread acceptThread;
    ClientHandler clientHandler;
    std::map<int, std::shared_ptr<ClientSession>> clientSessions;

    void acceptLoop();
    void handleClient(int clientSocket);
    ErrorCode exchangeProtocols(ClientSession& session);
public:
    NetUtils utils;
    NetworkServer() : sockfd(-1), sockStatus(SocketStatus::DISCONNECTED), running(false) {}
    ~NetworkServer();
    
    ErrorCode start(uint16_t _port, const std::string& _bindAddress = "127.0.0.1");
    void stop();
    void setClientHandler(ClientHandler handler);
    void setServerProtocol(const std::string& protocol);
    SocketStatus getStatus() const;
    uint16_t getPort() const;
    const std::string& getBindAddress() const;
    size_t getClientCount() const;
};

