#pragma once

#include <TCPPacket.hpp>
#include <TypeDefs.hpp>

// TODO: See if it can be made private inheritance
class SSHPacket : public TCPPacket {
private:
    // Payload is defined in TCPPacket
    Byte msgType;
    Byte paddingLength;
    Bytes padding;
public:
    static constexpr uint32_t HEADER_SIZE = 5;  // 4 bytes length + 1 byte padding length
    static constexpr uint32_t MAX_SIZE = 35000; // RFC 4253 recommends 32768
     
    SSHPacket() : msgType(0), padding(0), paddingLength(4) {}
    explicit SSHPacket(Byte _msgType) : msgType(_msgType), padding(0), paddingLength(4) {}
    ~SSHPacket() override = default;

    Byte getMsgType() const;
    void setMsgType(Byte _msgType);

    void setPaddingLength(Byte length);
    Byte getPaddingLength() const;

    void generatePadding();
    Bytes serialize() const override;
    void deserialize(const Bytes& data) override;

    uint32_t getSize() const override;
};
