#pragma once

#include <TypeDefs.hpp>

class TCPPacket {
protected:
    Bytes payload;
public:
    static const MAX_TCP_PACKET_LENGTH 30000;
    
    TCPPacket() = default;
    virtual ~TCPPacket() = default;

    virtual Bytes serialize() const;
    virtual void deserialize(const Bytes& data);

    virtual uint32_t getSize() const;
};

