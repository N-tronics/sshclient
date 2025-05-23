#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include <NetworkServer.hpp>
#include <NetworkClient.hpp>
#include <TypeDefs.hpp>
#include <TCPPacket.hpp>
#include <SSHServer.hpp>
#include <SSHClient.hpp>

using namespace ssh;
void testNetwork(char c) {
    if (c == 's') {
        std::thread serverThread([] () {
            NetworkServer server;
            server.setServerProtocol("TCP-SERVER");

            server.setClientHandler([] (ClientSession& session) {
                std::cout << "Client connected from " << session.getClientAddress() << std::endl;

                TCPPacket packet;
                if (session.utils.recvTCPPacket(packet) == ErrorCode::SUCCESS) {
                    std::cout << "Recvd message: " << std::string(packet.getPayload().begin(), packet.getPayload().end()) << std::endl;

                    TCPPacket response;
                    std::string respMsg = "Server recved ur msg";
                    Bytes respPayload(respMsg.begin(), respMsg.end());
                    response.setPayload(respPayload);
                    session.utils.sendTCPPacket(response);
                }

                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::cout << "Client session has ended" << std::endl;
            });

            server.start(3490);
            std::this_thread::sleep_for(std::chrono::seconds(10));
            server.stop();
        });
        std::this_thread::sleep_for(std::chrono::seconds(1));
        serverThread.join();
    } else {

        NetworkClient client;
        client.setClientProtocol("TCP-CLIENT");
        if (client.connectTo("127.0.0.1", 3490) != ErrorCode::SUCCESS)
            std::cout << "Failed to connect to server" << std::endl;
        else {
            std::cout << "Connected to server" << std::endl;
    
            TCPPacket packet;
            std::string msg = "Hello from client";
            packet.setPayload(Bytes(msg.begin(), msg.end()));
    
            if (client.utils.sendTCPPacket(packet) != ErrorCode::SUCCESS)
                std::cout << "Failed to send packet to server" << std::endl;
            else {
                std::cout << "Packet sent to server" << std::endl;
    
                TCPPacket resp;
                if (client.utils.recvTCPPacket(resp) != ErrorCode::SUCCESS)
                    std::cout << "Couldn't recv packet from server" << std::endl;
                else {
                    std::string respMsg(resp.getPayload().begin(), resp.getPayload().end());
                    std::cout << "Recvd response: " << respMsg << std::endl;
                }
            }
    
            client.disconnect();
        }
    }
}

void runDemoClient(std::string host = "127.0.0.1", uint32_t port = 2222) {
    std::cout << "Connecting to server..." << std::endl;

    SSHClient client;
    client.setClientProtocol("SSH-CLIENT");
    ErrorCode res = client.connectTo(host, port);
    if (res != ErrorCode::SUCCESS) {
        std::cout << "Couldn't connect to server" << std::endl;
        return;
    }

    std::cout << "Connected securely to server" << std::endl << std::endl;
    for (int _ = 0; _ < 5; _++)
        std::cout << "*";
    std::cout << "ENCRYPTED SESSION";
    for (int _ = 0; _ < 5; _++)
        std::cout << "*";
    std::cout << std::endl;

    SSHPacket packet(1);
    std::string msg = "Hello from SSH Client";
    packet.setPayload(Bytes(msg.begin(), msg.end()));
    res = client.sshUtils.sendSSHPacket(packet);
    if (res != ErrorCode::SUCCESS) {
        std::cout << "Couldnt send packet" << std::endl;
        return;
    }

    SSHPacket reply;
    res = client.sshUtils.recvSSHPacket(reply);
    if (res != ErrorCode::SUCCESS) {
        std::cout << "Couldnt recv packet" << std::endl;
        return;
    }
    std::string replyMsg(reply.getPayload().begin(), reply.getPayload().end());
    std::cout << "recvd : " << replyMsg << std::endl;

    client.disconnect();
    std::cout << std::endl;
    for (int _ = 0; _ < 27; _++)
        std::cout << "*";
    std::cout << std::endl;
    std::cout << "Disconnected from server" << std::endl;
}

void runDemoServer() {
    std::thread serverThread([] () {
        std::cout << "Starting SSH server on port 2222..." << std::endl;
        SSHServer server;
        server.setServerProtocol("SSH-SERVER");
        server.setSSHClientHandler([](SSHSession& session) {
            std::cout << "Waiting for message from client...";
            SSHPacket clientMsgPacket;
            if (session.sshUtils.recvSSHPacket(clientMsgPacket) != ErrorCode::SUCCESS) {
                std::cout << std::endl <<"Couldn't recv client packet" << std::endl;
                return; 
            }
            std::cout << "done" << std::endl;
            std::string clientMsg(clientMsgPacket.getPayload().begin(), clientMsgPacket.getPayload().end());
            std::cout << "Received message: " << clientMsg << std::endl << std::endl;
            
            std::cout << "Sending reply...";
            SSHPacket replyPacket(static_cast<Byte>(MsgType::IGNORE));
            std::string reply = "Received message: " + clientMsg;
            replyPacket.setPayload(Bytes(reply.begin(), reply.end()));
            if (session.sshUtils.sendSSHPacket(replyPacket) != ErrorCode::SUCCESS) {
                std::cout << std::endl << "Couldn't send reply msg" << std::endl;
                return;
            }
            std::cout << "done" << std::endl << std::endl;
        });
        server.startSSH(2222);
        std::cout << "Server started. Press Enter to stop..." << std::endl;
        std::cin.get();
        std::cout << "Stopping server..." << std::endl;
        server.stop();
    });
    std::this_thread::sleep_for(std::chrono::seconds(1));
    serverThread.join();
}

void printUsage() {
    std::cout << "Usage: " << std::endl;
    std::cout << "sshctrl demo <c/s>: Runs demo of unencrypted network of client/server" << std::endl;
    std::cout << "sshctrl server: Starts an SSH Server on localhost at port 2222" << std::endl;
    std::cout << "sshctrl client: Connects to SSH Server on localhost at port 2222, if server is running" << std::endl;
    std::cout << "sshctrl client <host> <port>: Connects to SSH Server on the given address" << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printUsage();
    }
    std::string mode = argv[1];
    if (mode == "demo" && argc == 3) {
        testNetwork(argv[2][0]);
    }
    else if (mode == "server")
        runDemoServer();
    else if (mode == "client" && (argc == 4 || argc == 2)) {
        if (argc == 2)
            runDemoClient();
        else
            runDemoClient(std::string(argv[2]), std::atoi(argv[3]));
    } else {
        printUsage();
        return 1;
    }

    return 0;
}

