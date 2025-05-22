#include <SSHClient.hpp>
#include <SSHPacket.hpp>
#include <Crypto.hpp>
#include <TypeDefs.hpp>
#include <MathFns.hpp>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <cstring>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <NetworkClient.hpp>

namespace ssh {

ErrorCode SSHClient::performKEX() {
    std::cout << "Starting key exchange with server..." << std::endl;

    SSHPacket kexInitPacket(static_cast<Byte>(MsgType::KEXINIT));
    Bytes cookie = crypto::Random::generateBytes(16);

    Bytes kexInitPayload = cookie;
    std::string kexAlgos = "diffie-hellman-group14-sha256";
    kexInitPayload.insert(kexInitPayload.end(), kexAlgos.begin(), kexAlgos.end());
        
    // Add server host key algorithms (ssh-rsa)
    std::string hostKeyAlgos = "ssh-rsa";
    kexInitPayload.insert(kexInitPayload.end(), hostKeyAlgos.begin(), hostKeyAlgos.end());
    
    // Add encryption algorithms (aes256-cbc)
    std::string encAlgos = "aes256-cbc";
    kexInitPayload.insert(kexInitPayload.end(), encAlgos.begin(), encAlgos.end());
    
    // Add MAC algorithms (hmac-sha256)
    std::string macAlgos = "hmac-sha256";
    kexInitPayload.insert(kexInitPayload.end(), macAlgos.begin(), macAlgos.end());
    
    // Add compression algorithms (none)
    std::string compAlgos = "none";
    kexInitPayload.insert(kexInitPayload.end(), compAlgos.begin(), compAlgos.end());
    
    // Add languages (empty)
    kexInitPayload.push_back(0);
    
    // Add first_kex_packet_follows (false)
    kexInitPayload.push_back(0);

    // Add reserved (0)
    for (int i = 0; i < 4; i++)
        kexInitPayload.push_back(0);

    kexInitPacket.setPayload(kexInitPayload);
    kexInitPacket.generatePadding();
    
    // Send packet
    std::cout << "Sending KEXINIT..." << std::endl;
    ErrorCode result = utils.sendTCPPacket(kexInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEXINIT: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Waiting for server's KEXINIT" << std::endl;
    SSHPacket serverKexInitPacket;
    result = utils.recvTCPPacket(serverKexInitPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEXINIT: " << static_cast<int>(result) << std::endl;
    }

    if (serverKexInitPacket.getMsgType() != static_cast<Byte>(MsgType::KEXINIT)) {
        std::cout << "Invalid message type received: " << static_cast<int>(serverKexInitPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Received server KEXINIT" << std::endl;
    
    serverKexInit = serverKexInitPacket.getPayload();
    clientKexInit = kexInitPacket.getPayload();

    std::cout << "Generating ECDH Key pair..." << std::endl;
    // ECDH
    std::unique_ptr<crypto::ecdh::ECDH> ecdh = std::make_unique<crypto::ecdh::ECDH>("brainpoolP256r1");
    ecdh->generateKeys();
    
    SSHPacket dhInitPacket(static_cast<Byte>(MsgType::KEX_DH_INIT));
    Bytes dhInitPayload;
    crypto::ecdh::Point publicKeyPoint = ecdh->getPublicKeyPoint();
    Bytes publicKeyX = numToBytes(publicKeyPoint.x, 32), publicKeyY = numToBytes(publicKeyPoint.y, 32);
    dhInitPayload.insert(dhInitPayload.end(), publicKeyX.begin(), publicKeyX.end());
    dhInitPayload.insert(dhInitPayload.end(), publicKeyY.begin(), publicKeyY.end());
    dhInitPacket.setPayload(dhInitPayload);
    dhInitPacket.generatePadding();
    
    std::cout << "Sending KEX_DH_INIT..." << std::endl;
    result = utils.sendTCPPacket(dhInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEX_DH_INIT: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Waiting for server's KEX_DH_REPLY" << std::endl;
    SSHPacket dhReplyPacket;
    result = utils.recvTCPPacket(dhReplyPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEX_DH_REPLY: " << static_cast<int>(result) << std::endl;
    }

    if (dhReplyPacket.getMsgType() != static_cast<Byte>(MsgType::KEX_DH_REPLY)) {
        std::cout << "Invalid message type received: " << static_cast<int>(dhReplyPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Received server KEX_DH_REPLY" << std::endl;

    const Bytes& replyPayload = dhReplyPacket.getPayload();
    
    crypto::ecdh::Point serverPublicKeyPoint(ecdh->getCurve());
    serverPublicKeyPoint.x = bytesToNum(Bytes(
        replyPayload.begin(),
        replyPayload.begin() + 32
    ));
    serverPublicKeyPoint.y = bytesToNum(Bytes(
        replyPayload.begin() + 32 + 1,
        replyPayload.begin() + 32 * 2
    ));

    crypto::rsa::RSAKey serverRSAKey;
    serverRSAKey.exp = bytesToNum(Bytes(
        replyPayload.begin() + 32 * 2 + 1,
        replyPayload.begin() + 32 * 3
    ));
    serverRSAKey.prime = bytesToNum(Bytes(
        replyPayload.begin() + 32 * 3 + 1,
        replyPayload.begin() + 32 * 4
    ));
    Bytes serverSignedHash(replyPayload.begin() + 32 * 4 + 1, replyPayload.end());

    std::cout << "Computing shared secret..." << std::endl;
    crypto::ecdh::Point sharedSecretPoint = ecdh->getPrivateKey() * serverPublicKeyPoint;
    num_t sharedSecret = sharedSecretPoint.x;

    std::cout << "Computing exchange hash..." << std::endl;
    Bytes exchangeHash = sshUtils.computeExchangeHash(
        Bytes(clientProtocol.begin(), clientProtocol.end()),
        Bytes(serverProtocol.begin(), serverProtocol.end()),
        clientKexInit,
        serverKexInit,
        numToBytes(ecdh->getPublicKey()),
        numToBytes(serverPublicKeyPoint.x),
        numToBytes(sharedSecret)
    );
    
    // Verify exchange hashes
    crypto::rsa::RSA rsa;
    if (rsa.verifySignature(exchangeHash, serverSignedHash, serverRSAKey)) {
        std::cout << "Exchange hash invalid!" << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Exchange hash verified" << std::endl;

    if (sshUtils.sessionId.empty())
        sshUtils.sessionId = exchangeHash;

    std::cout << "Deriving encryption keys..." << std::endl;
    sshUtils.deriveKeys(numToBytes(sharedSecret), exchangeHash, "Client");

    std::cout << "Sending NEWKEYS..." << std::endl;
    SSHPacket newKeys(static_cast<Byte>(MsgType::NEWKEYS));
    newKeys.generatePadding();
    result = utils.sendTCPPacket(newKeys);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send NEWKEYS" << std::endl;
        NetworkClient::disconnect();
        return result;
    }

    std::cout << "Waiting for server's NEWKEYS..." << std::endl;
    SSHPacket serverNewKeysPacket;
    result = utils.recvTCPPacket(serverNewKeysPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to receive NEWKEYS: " << static_cast<int>(result) << std::endl;
        NetworkClient::disconnect();
        return result;
    }
    if (serverNewKeysPacket.getMsgType() != static_cast<Byte>(MsgType::NEWKEYS)) {
        std::cout << "Invalid Message Type received: " << static_cast<Byte>(serverNewKeysPacket.getMsgType()) << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }

    std::cout << "Received server NEWKEYS" << std::endl;
    std::cout << "Enabling encryption..." << std::endl;
    kexComplete = true;
    encryptionEnabled = true;
    
    std::cout << "Key Exchange completed successfully!" << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode SSHClient::connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms) {
    ErrorCode result = NetworkClient::connectTo(_hostName, _port, timeout_ms);
    if (result != ErrorCode::SUCCESS)
        return result;
    sshUtils = SSHUtils(utils);

    if (serverProtocol.substr(0, 4) != "SSH-") {
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }

    result = performKEX();
    if (result != ErrorCode::SUCCESS) {
        NetworkClient::disconnect();
        return result;
    }

    // Verify socket state after key exchange
    int error = 0;
    socklen_t len = sizeof(error);
    int retval = getsockopt(*sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval != 0 || error != 0) {
        std::cout << "Socket error after key exchange: " << strerror(error) << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::CONNECTION_FAILED;
    }
    std::cout << "Socket verified in good state after key exchange" << std::endl;
    
    // Send service request for ssh-connection
    std::cout << "Sending service request..." << std::endl;
    SSHPacket serviceRequest(static_cast<Byte>(MsgType::SERVICE_REQUEST));
    std::string serviceName = "ssh-connection";
    Bytes serviceNameBytes(serviceName.begin(), serviceName.end());
    serviceRequest.setPayload(serviceNameBytes);
    serviceRequest.generatePadding();
    
    result = sshUtils.sendSSHPacket(serviceRequest);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send service request: " << static_cast<int>(result) << std::endl;
        return result;
    }
    
    // Wait for service accept
    std::cout << "Waiting for service accept..." << std::endl;
    SSHPacket serviceAccept;
    result = sshUtils.recvSSHPacket(serviceAccept);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to receive service accept: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (serviceAccept.getMsgType() != static_cast<Byte>(MsgType::SERVICE_ACCEPT)) {
        std::cout << "Invalid message type received: " << static_cast<int>(serviceAccept.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Service request accepted" << std::endl;

    return ErrorCode::SUCCESS;
}
    
}; // namespace ssh
