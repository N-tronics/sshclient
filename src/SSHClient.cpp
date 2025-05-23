#include <SSHClient.hpp>
#include <SSHPacket.hpp>
#include <Crypto.hpp>
#include <TypeDefs.hpp>
#include <MathFns.hpp>
#include <NetworkClient.hpp>
#include <SocketUtils.hpp>
#include <string>
#include <cstring>
#include <iostream>

namespace ssh {

ErrorCode SSHClient::performKEX() {
    std::cout << "Starting KEX with server..." << std::endl;

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
    std::cout << "Sending client KEXINIT...";
    ErrorCode result = utils.sendTCPPacket(kexInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to send KEXINIT: " << static_cast<int>(result) << std::endl;
        return result;
    }
    std::cout << "done" << std::endl;

    std::cout << "Waiting for server KEXINIT...";
    SSHPacket serverKexInitPacket;
    result = utils.recvTCPPacket(serverKexInitPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to recv KEXINIT: " << static_cast<int>(result) << std::endl;
    }
    if (serverKexInitPacket.getMsgType() != static_cast<Byte>(MsgType::KEXINIT)) {
        std::cout << std::endl << "Invalid message type received: " << static_cast<int>(serverKexInitPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "received" << std::endl;
    
    serverKexInit = serverKexInitPacket.getPayload();
    clientKexInit = kexInitPacket.getPayload();
    
    std::cout << "Client KEXINIT Payload: "; printBytes(std::cout, clientKexInit); std::cout << std::endl;
    std::cout << "Server KEXINIT Payload: "; printBytes(std::cout, serverKexInit); std::cout << std::endl;

    std::cout << std::endl << "Generating ECDH Key pair...";
    // ECDH
    crypto::ecdh::ECDH ecdh("brainpoolP256r1");
    ecdh.generateKeys();
    std::cout << "done" << std::endl;
    
    SSHPacket dhInitPacket(static_cast<Byte>(MsgType::KEX_DH_INIT));
    Bytes dhInitPayload;
    crypto::ecdh::Point publicKeyPoint = ecdh.getPublicKeyPoint();
    Bytes publicKeyX = numToBytes(publicKeyPoint.x, 32), publicKeyY = numToBytes(publicKeyPoint.y, 32);
    dhInitPayload.insert(dhInitPayload.end(), publicKeyX.begin(), publicKeyX.end());
    dhInitPayload.insert(dhInitPayload.end(), publicKeyY.begin(), publicKeyY.end());
    dhInitPacket.setPayload(dhInitPayload);
    dhInitPacket.generatePadding();

    std::cout << "ECDH Client Private key: "; printBytes(std::cout, numToBytes(ecdh.getPrivateKey())); std::cout << std::endl;
    std::cout << "ECDH Client Public  key: "; printBytes(std::cout, numToBytes(ecdh.getPublicKey())); std::cout << std::endl;
    
    std::cout << "Sending KEX_DH_INIT...";
    result = utils.sendTCPPacket(dhInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to send KEX_DH_INIT: " << static_cast<int>(result) << std::endl;
        return result;
    }
    std::cout << "done" << std::endl;

    std::cout << "Waiting for server KEX_DH_REPLY..." << std::endl;
    SSHPacket dhReplyPacket;
    result = utils.recvTCPPacket(dhReplyPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to recv KEX_DH_REPLY: " << static_cast<int>(result) << std::endl;
    }
    if (dhReplyPacket.getMsgType() != static_cast<Byte>(MsgType::KEX_DH_REPLY)) {
        std::cout << std::endl << "Invalid message type received: " << static_cast<int>(dhReplyPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "done" << std::endl << std::endl;

    const Bytes& replyPayload = dhReplyPacket.getPayload();
    
    crypto::ecdh::Point serverPublicKeyPoint(ecdh.getCurve());
    serverPublicKeyPoint.x = bytesToNum(Bytes(
        replyPayload.begin(),
        replyPayload.begin() + 32
    ));
    serverPublicKeyPoint.y = bytesToNum(Bytes(
        replyPayload.begin() + 32,
        replyPayload.begin() + 32 * 2
    ));

    crypto::rsa::RSAKey serverRSAKey;
    serverRSAKey.exp = bytesToNum(Bytes(
        replyPayload.begin() + 32 * 2,
        replyPayload.begin() + 32 * 2 + 128
    ));
    serverRSAKey.prime = bytesToNum(Bytes(
        replyPayload.begin() + 32 * 2 + 128,
        replyPayload.begin() + 32 * 2 + 128 + 128
    ));
    Bytes serverSignedHash(replyPayload.begin() + 32 * 2 + 256, replyPayload.end());
    
    std::cout << "Server ECDH Public Key: "; printBytes(std::cout, numToBytes(serverPublicKeyPoint.x)); std::cout << std::endl;
    std::cout << "Server RSA exp: "; printBytes(std::cout, numToBytes(serverRSAKey.exp)); std::cout << std::endl;
    std::cout << "Server RSA prime: "; printBytes(std::cout, numToBytes(serverRSAKey.prime)); std::cout << std::endl;
    std::cout << "Server signed hash: "; printBytes(std::cout, serverSignedHash); std::cout << std::endl;

    std::cout << "Computing shared secret...";
    crypto::ecdh::Point sharedSecretPoint = ecdh.getPrivateKey() * serverPublicKeyPoint;
    num_t sharedSecret = sharedSecretPoint.x;
    std::cout << "done" << std::endl;
    std::cout << "ECDH Client Shared secret: "; printBytes(std::cout, numToBytes(sharedSecret)); std::cout << std::endl;

    std::cout << "Computing exchange hash...";
    Bytes exchangeHash = sshUtils.computeExchangeHash(
        Bytes(clientProtocol.begin(), clientProtocol.end()),
        Bytes(serverProtocol.begin(), serverProtocol.end()),
        clientKexInit,
        serverKexInit,
        numToBytes(ecdh.getPublicKey()),
        numToBytes(serverPublicKeyPoint.x),
        numToBytes(sharedSecret)
    );
    std::cout << "done" << std::endl;
    std::cout << "Exchange Hash: "; printBytes(std::cout, exchangeHash); std::cout << std::endl;
    
    // Verify exchange hashes
    crypto::rsa::RSA rsa;
    std::cout << "Verifying exchange hash...";
    if (!rsa.verifySignature(exchangeHash, serverSignedHash, serverRSAKey)) {
        std::cout << std::endl << "Exchange hash invalid!" << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "done" << std::endl;

    if (sshUtils.sessionID.empty())
        sshUtils.sessionID = exchangeHash;

    std::cout << "Deriving encryption keys..." << std::endl;
    sshUtils.deriveKeys(numToBytes(sharedSecret), exchangeHash, "Client");
    std::cout << "done" << std::endl << std::endl;

    std::cout << "Sending NEWKEYS...";
    SSHPacket newKeys(static_cast<Byte>(MsgType::NEWKEYS));
    newKeys.generatePadding();
    result = utils.sendTCPPacket(newKeys);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to send NEWKEYS" << std::endl;
        NetworkClient::disconnect();
        return result;
    }
    std::cout << "done" << std::endl;

    std::cout << "Waiting for server's NEWKEYS...";
    SSHPacket serverNewKeysPacket;
    result = utils.recvTCPPacket(serverNewKeysPacket, SSHPacket::MAX_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to receive NEWKEYS: " << static_cast<int>(result) << std::endl;
        NetworkClient::disconnect();
        return result;
    }
    if (serverNewKeysPacket.getMsgType() != static_cast<Byte>(MsgType::NEWKEYS)) {
        std::cout << std::endl << "Invalid Message Type received: " << static_cast<Byte>(serverNewKeysPacket.getMsgType()) << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "done" << std::endl;

    std::cout << "Enabling encryption...";
    kexComplete = true;
    encryptionEnabled = true;
    std::cout << "done" << std::endl;
    
    std::cout << "Key Exchange completed successfully!" << std::endl << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode SSHClient::connectTo(const std::string& _hostName, uint16_t _port, uint32_t timeout_ms) {
    ErrorCode result = NetworkClient::connectTo(_hostName, _port, timeout_ms);
    if (result != ErrorCode::SUCCESS)
        return result;
    sshUtils = SSHUtils(utils);

    if (serverProtocol.substr(0, 4) != "SSH-") {
        std::cout << "Connected server does not follow SSH protocol" << std::endl;
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
    SSHPacket serviceRequest(static_cast<Byte>(MsgType::SERVICE_REQUEST));
    std::string serviceName = "ssh-connection";
    Bytes serviceNameBytes(serviceName.begin(), serviceName.end());
    serviceRequest.setPayload(serviceNameBytes);
    serviceRequest.generatePadding();
    
    std::cout << "Sending service request...";
    result = sshUtils.sendSSHPacket(serviceRequest);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl <<"Failed to send service request: " << static_cast<int>(result) << std::endl;
        return result;
    }
    std::cout << "done" << std::endl;
    
    // Wait for service accept
    std::cout << "Waiting for service accept...";
    SSHPacket serviceAccept;
    result = sshUtils.recvSSHPacket(serviceAccept);
    if (result != ErrorCode::SUCCESS) {
        std::cout << std::endl << "Failed to receive service accept: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (serviceAccept.getMsgType() != static_cast<Byte>(MsgType::SERVICE_ACCEPT)) {
        std::cout << std::endl << "Invalid message type received: " << static_cast<int>(serviceAccept.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "done" << std::endl;

    return ErrorCode::SUCCESS;
}
    
}; // namespace ssh
