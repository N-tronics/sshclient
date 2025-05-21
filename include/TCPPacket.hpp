#pragma once

#include <TypeDefs.hpp>

class TCPPacket {
protected:
    Bytes payload;
public:
    static const uint32_t MAX_TCP_PACKET_SIZE = 30000;
    
    TCPPacket() = default;
    virtual ~TCPPacket() = default;

    virtual Bytes serialize() const;
    virtual void deserialize(const Bytes& data);

    const Bytes& getPayload() const;
    void setPayload(const Bytes& _payload);
    void appendToPayload(const Bytes& data);

    virtual uint32_t getSize() const;
};

