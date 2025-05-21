#pragma once

#include <TypeDefs.hpp>
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

class ClientSession {
private:
    int sockfd;
    std::string clientAddress;
    std::string clientProtocol;
    std::string serverProtocol;
    SocketStatus sockStatus;

public:
    NetUtils utils;
    ClientSession(int _sockfd, const std::string& _clientAddress, const std::string& _serverProtocol);
    ~ClientSession();

    void disconnect();
    int getSocket() const;
    const std::string& getClientAddress() const;
    SocketStatus getSockStatus() const;
    const std::string& getClientProtocol() const;
    void setClientProtocol(const std::string& protocol);
};

