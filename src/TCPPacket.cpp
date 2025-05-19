#include <TCPPacket.hpp>
#include <TypeDefs.hpp>
#include <stdexcept>

Bytes TCPPacket::serialize() const {
    Bytes data;
    uint32_t packetLength = 4 + payload.size();
    data.reserve(packetLength);

    data.push_back((packetLength >> 24) & 0xFF);
    data.push_back((packetLength >> 16) & 0xFF);
    data.push_back((packetLength >>  8) & 0xFF);
    data.push_back( packetLength        & 0xFF);

    data.insert(data.end(), payload.begin(), payload.end());

    return data;
}

void deserialize(const Bytes& data) {
    if (data.size() <= 4)
        throw std::runtime_error("Packet data too small");
    uint32_t packetLength = 
        (data[0] << 24) |
        (data[1] << 16) |
        (data[2] <<  8) |
         data[3];        

    if (data.size() < 4 + packetLength)
        throw std::runtime_error("Incomplete packet data");

    payload.resize(packetLength);
    payload.insert(payload.begin(), data.begin() + 4, data.begin() + 4 + packetLength);
}
    
uint32_t getSize() const {
    return 4 + payload.size();
}
