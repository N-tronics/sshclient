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

using namespace ssh;
int main(int argc, char *argv[]) {
    if (argv[1][0] == 's') {
        std::thread serverThread([] () {
            std::cout << "Starting ssh server on port 2222..." << std::endl;
            SSHServer server;
            server.setServerProtocol("SSH-SERVER");
            server.setSSHClientHandler([](SSHSession& session) {
                std::cout << "Client Connected from " << session.getClientAddress() << std::endl;
                std::cout << "Client protocol: " << session.getClientProtocol() << std::endl;

                SSHPacket clientMsgPacket;
                if (session.sshUtils.recvSSHPacket(clientMsgPacket) != ErrorCode::SUCCESS) {
                    std::cout << "Couldn't recv client packet" << std::endl;
                    return 1;
                }
                std::string clientMsg(clientMsgPacket.getPayload().begin(), clientMsgPacket.getPayload().end());
                std::cout << "Recvd msg: " << clientMsg << std::endl;

                SSHPacket replyPacket(static_cast<Byte>(MsgType::IGNORE));
                std::string reply = "Recvd ur msg: " + clientMsg;
                replyPacket.setPayload(Bytes(reply.begin(), reply.end()));
                if (session.sshUtils.sendSSHPacket(replyPacket) != ErrorCode::SUCCESS) {
                    std::cout << "Couldn't send reply msg" << std::endl;
                    return 1;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
                // while (true) {
                //     SSHPacket cmdPacket;
                //     if (session.sshUtils.recvSSHPacket(cmdPacket) != ErrorCode::SUCCESS) {
                //         std::cout << "Couldn't recv cmd packet" << std::endl;
                //         return 1;
                //     }
                //     std::string clientMsg(cmdPacket.getPayload().begin(), cmdPacket.getPayload().end());
                //     std::cout << "EXECUTING CMD: " << clientMsg << std::endl;
                // }
                
                std::cout << "Client session has ended" << std::endl;
                return 0;
            });
            server.startSSH(2222);
            // std::this_thread::sleep_for(std::chrono::seconds(20));
            // server.stop();
            std::cout << "Server started. Press Enter to stop..." << std::endl;
            std::cin.get();
            std::cout << "Stopping server..." << std::endl;
            server.stop();
            std::cout << "Server stopped" << std::endl;
        });
        std::this_thread::sleep_for(std::chrono::seconds(1));
        serverThread.join();
    } else {
        std::cout << "Connecting to server..." << std::endl;

        SSHClient client;
        client.setClientProtocol("SSH-CLIENT");
        ErrorCode res = client.connectTo("127.0.0.1", 2222);
        if (res != ErrorCode::SUCCESS) {
            std::cout << "Couldn't connect to server" << std::endl;
            return 1;
        }

        std::cout << "Connected to server" << std::endl;

        SSHPacket packet(1);
        std::string msg = "Hello from SSH Client";
        packet.setPayload(Bytes(msg.begin(), msg.end()));
        res = client.sshUtils.sendSSHPacket(packet);
        if (res != ErrorCode::SUCCESS) {
            std::cout << "Couldnt send packet" << std::endl;
            return 1;
        }

        SSHPacket reply;
        res = client.sshUtils.recvSSHPacket(reply);
        if (res != ErrorCode::SUCCESS) {
            std::cout << "Couldnt recv packet" << std::endl;
            return 1;
        }
        std::string replyMsg(reply.getPayload().begin(), reply.getPayload().end());
        std::cout << "recvd : " << replyMsg << std::endl;

        // while (true) {
        //     std::string cmd;
        //     std::getline(std::cin, cmd);
        //     if (cmd == "quit")
        //         break;

        //     SSHPacket cmdPacket(1);
        //     cmdPacket.setPayload(Bytes(cmd.begin(), cmd.end()));
        //     res = client.sshUtils.sendSSHPacket(cmdPacket);
        //     if (res != ErrorCode::SUCCESS) {
        //         std::cout << "Couldnt send packet" << std::endl;
        //         return 1;
        //     }
        // }
        client.disconnect();
        std::cout << "Disconnected from server" << std::endl;
    }
}

