#include <SSHServer.hpp>
#include <MathFns.hpp>

namespace ssh {

SSHServer::~SSHServer() {
    stop();
}

void SSHServer::handleClientConnection(ClientSession& _session) {
    std::cout << "Starting KEX with client..." << std::endl;

    SSHSession session(_session);
    if (performKEX(session) != ErrorCode::SUCCESS) {
        std::cout << "KEX Failed! Couldn't recv client's KEXINIT." << std::endl;
        return;
    }
    std::cout << "KEX Completed successfully!" << std::endl;

    std::cout << "Waiting for service request..." << std::endl;
    SSHPacket serviceRequest;
    ErrorCode result = session.sshUtils.recvSSHPacket(serviceRequest);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv service request: " << static_cast<int>(result) << std::endl;
        return;
    }
    if (serviceRequest.getMsgType() != static_cast<Byte>(MsgType::SERVICE_REQUEST)) {
        std::cout << "Invalid message type recvd: " << serviceRequest.getMsgType() << std::endl;
    }
    std::cout << "Recvd service request" << std::endl;

    std::cout << "Sending service accept..." << std::endl;
    SSHPacket serviceAccept(static_cast<Byte>(MsgType::SERVICE_ACCEPT));
    std::string serviceName = "ssh-connection";
    Bytes serviceNameBytes(serviceName.begin(), serviceName.end());
    serviceAccept.setPayload(serviceNameBytes);
    serviceAccept.generatePadding();

    result = session.sshUtils.sendSSHPacket(serviceAccept);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send service accept: " << static_cast<int>(result) << std::endl;
        return;
    }
    std::cout << "Service request sent." << std::endl;

    if (sshClientHandler) {
        std::cout << "Calling Client Handler... " << std::endl;
        sshClientHandler(session);
    }

    std::cout << "Client Session Completed Successfully" << std::endl;
}

ErrorCode SSHServer::performKEX(SSHSession& session) {
    SSHPacket clientKexInitPacket;
    std::cout << "Waiting for KEXINIT packet..." << std::endl;
    ErrorCode result = session.sshUtils.recvTCPPacket(clientKexInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEXINIT: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (clientKexInitPacket.getMsgType() != static_cast<Byte>(MsgType::KEXINIT)) {
        std::cout << "Invalid msg type recvd: " << clientKexInitPacket.getMsgType() << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Recvd client KEXINIT" << std::endl;
    Bytes clientKexInit = clientKexInitPacket.getPayload();

    SSHPacket serverKexInitPacket(static_cast<Byte>(MsgType::KEXINIT));
    Bytes cookie = crypto::Random::generateBytes(16);
    Bytes kexInitPayload = cookie;
    // Add key exchange algorithms (diffie-hellman-group14-sha256)
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
    for (int i = 0; i < 4; ++i) {
        kexInitPayload.push_back(0);
    }
    serverKexInitPacket.setPayload(kexInitPayload);
    serverKexInitPacket.generatePadding();
    Bytes serverKexInit = kexInitPayload;

    // Sending Server's KEXINIT
    std::cout << "Sending server KEXINIT" << std::endl;    
    result = session.sshUtils.sendTCPPacket(serverKexInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEXINIT: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Waiting for client's KEX_DH_INIT..." << std::endl;
    SSHPacket dhInitPacket;
    result = session.sshUtils.recvTCPPacket(dhInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEX_DH_INIT: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (dhInitPacket.getMsgType() != static_cast<Byte>(MsgType::KEX_DH_INIT)) {
        std::cout << "Invalid msg type recvd: " << dhInitPacket.getMsgType() << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Client's KEX_DH_INIT recvd" << std::endl;
    
    crypto::ecdh::ECDH ecdh("brainpoolP256r1");
    ecdh.generateKeys();
    crypto::ecdh::Point clientPublicKeyPoint(ecdh.getCurve());

    Bytes clientPublicKeyBytes = dhInitPacket.getPayload();
    clientPublicKeyPoint.x = bytesToNum(Bytes(
        clientPublicKeyBytes.begin(),
        clientPublicKeyBytes.begin() + 32
    ));
    clientPublicKeyPoint.y = bytesToNum(Bytes(
        clientPublicKeyBytes.begin() + 33,
        clientPublicKeyBytes.end()
    ));

    std::cout << "Computing shared secret..." << std::endl;
    crypto::ecdh::Point sharedSecretPoint = ecdh.getPrivateKey() * clientPublicKeyPoint;
    num_t sharedSecret = sharedSecretPoint.x;
    
    std::cout << "Computing exchange hash..." << std::endl;
    Bytes exchangeHash = session.sshUtils.computeExchangeHash(
        Bytes(session.getClientProtocol().begin(), session.getClientProtocol().end()),
        Bytes(session.getServerProtocol().begin(), session.getServerProtocol().end()),
        clientKexInit,
        serverKexInit,
        numToBytes(clientPublicKeyPoint.x),
        numToBytes(ecdh.getPublicKey()),
        numToBytes(sharedSecret)
    );
    if (session.getSessionID().empty())
        session.setSessionID(exchangeHash);
    
    Bytes dhReplyPayload;
    crypto::ecdh::Point publicKeyPoint = ecdh.getPublicKeyPoint();
    Bytes publicKeyX = numToBytes(publicKeyPoint.x, 32), publicKeyY = numToBytes(publicKeyPoint.y, 32);
    dhReplyPayload.insert(dhReplyPayload.end(), publicKeyX.begin(), publicKeyX.end());
    dhReplyPayload.insert(dhReplyPayload.end(), publicKeyY.begin(), publicKeyY.end());

    dhReplyPayload.insert(dhReplyPayload.end(), serverRSAPublicKeyBytes.begin(), serverRSAPublicKeyBytes.end());
    
    Bytes signedHash = rsa.signBytes(exchangeHash);
    dhReplyPayload.insert(dhReplyPayload.end(), signedHash.begin(), signedHash.end());

    std::cout << "Sending KEX_DH_REPLY..." << std::endl;
    SSHPacket dhReply(static_cast<Byte>(MsgType::KEX_DH_REPLY));
    dhReply.setPayload(dhReplyPayload);
    dhReply.generatePadding();
    result = session.sshUtils.sendTCPPacket(dhReply);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEX_DH_REPLY: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Deriving encryption keys..." << std::endl;
    session.sshUtils.deriveKeys(numToBytes(sharedSecret), exchangeHash, "Server");


    SSHPacket newKeys(static_cast<Byte>(MsgType::NEWKEYS));
    std::cout << "Sending NEWKEYS..." << std::endl;
    result = session.sshUtils.sendTCPPacket(newKeys);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send NEWKEYS: " << static_cast<int>(result) << std::endl;
        return result;
    }
    
    // Wait for client's NEWKEYS packet
    std::cout << "Waiting for client's NEWKEYS..." << std::endl;
    SSHPacket clientNewKeys;
    result = session.sshUtils.recvTCPPacket(clientNewKeys);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to receive NEWKEYS: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (clientNewKeys.getMsgType() != static_cast<Byte>(MsgType::NEWKEYS)) {
        std::cout << "Invalid message type received: " << clientNewKeys.getMsgType() << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Received client NEWKEYS" << std::endl;

    std::cout << "Enabling Encryption..." << std::endl;
    session.enableEncryption();
    
    return ErrorCode::SUCCESS;
}

ErrorCode SSHServer::startSSH(uint16_t _port, const std::string& _bindAddress) {
    setClientHandler([this](ClientSession& session) {
        handleClientConnection(session);
    });
    
    rsa.generateKeyPair();
    crypto::rsa::RSAKey publicKey = rsa.getPublicKey();
    std::cout << "RSA Key exp: " << publicKey.exp << std::endl;
    std::cout << "RSA Key prime: " << publicKey.prime << std::endl;
    
    Bytes expBytes = numToBytes(publicKey.exp);
    Bytes primeBytes = numToBytes(publicKey.prime);
    
    serverRSAPublicKeyBytes.insert(serverRSAPublicKeyBytes.begin(), expBytes.begin(), expBytes.end());
    serverRSAPublicKeyBytes.insert(serverRSAPublicKeyBytes.end(), primeBytes.begin(), primeBytes.end());
    
    return start(_port, _bindAddress);
}

void SSHServer::setSSHClientHandler(SSHClientHandler handler) { sshClientHandler = handler; }

} // namespace
