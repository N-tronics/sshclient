#include <SSHPacket.hpp>
#include <Crypto.hpp>
#include <MathFns.hpp>

Byte SSHPacket::getMsgType() const { return msgType; }
void SSHPacket::setMsgType(Byte _msgType) { msgType = _msgType; }

void SSHPacket::setPaddingLength(Byte length) {
    paddingLength = length;
    padding.resize(paddingLength);
}
Byte SSHPacket::getPaddingLength() const { return paddingLength; }
uint32_t SSHPacket::getSize() const { return 4 + 1 + 1 + payload.size() + padding.size(); } // packetLength + paddingLength + msgType + payload + padding

void SSHPacket::generatePadding() {
    size_t contentSize = 1 + payload.size();
    size_t blockSize = crypto::AES256::BLOCK_SIZE;

    size_t minPaddingLength = 4;
    size_t remainder = (SSHPacket::HEADER_SIZE + contentSize + minPaddingLength) % blockSize;
    paddingLength = static_cast<Byte>(remainder == 0 ? minPaddingLength : minPaddingLength + blockSize - remainder);
    crypto::Random::generateBytes(padding, paddingLength);    
}

Bytes SSHPacket::serialize() const {
    uint32_t packetLength = 1 + 1 + payload.size() + padding.size();
    Bytes result;

    result.push_back((packetLength >> 24) & 0xFF);
    result.push_back((packetLength >> 16) & 0xFF);
    result.push_back((packetLength >>  8) & 0xFF);
    result.push_back( packetLength        & 0xFF);

    result.push_back(static_cast<uint8_t>(padding.size()));
    result.push_back(msgType);

    result.insert(result.end(), payload.begin(), payload.end());
    result.insert(result.end(), padding.begin(), padding.end());

    return result;
}

void SSHPacket::deserialize(const Bytes& data) {
    if (data.size() < 5)
        throw std::runtime_error("Packet data too small");

    uint32_t packetLength =
        (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) <<  8) |
         static_cast<uint32_t>(data[3]);

    if (packetLength > SSHPacket::MAX_SIZE)
        throw std::runtime_error("Packet size too big");
    if (packetLength + 4 > data.size()) {
        std::cout << data.size() << std::endl;
        throw std::runtime_error("Incomplete packet data");
    }
    
    Byte paddingLength = data[4];
    if (paddingLength > packetLength - 1) // TODO: Verifiy condition
        throw std::runtime_error("Invalid packet length");

    msgType = data[5];

    size_t payloadLength = packetLength - paddingLength - 2;
    payload = Bytes(data.begin() + 6, data.begin() + 6 + payloadLength);

    //padding.resize(paddingLength);
    padding.insert(padding.begin(), data.begin() + 6 + payloadLength, data.begin() + 6 + payloadLength + paddingLength);
}

