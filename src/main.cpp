#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include <NetworkServer.hpp>
#include <NetworkClient.hpp>
#include <TypeDefs.hpp>
#include <TCPPacket.hpp>

int main(int argc, char *argv[]) {
    if (argv[1][0] == 's') {
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
            std::this_thread::sleep_for(std::chrono::seconds(20));
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

