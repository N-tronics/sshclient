# SSH Client-Server Implementation

This project is an implementation of an SSH client and server in C++ from scratch. The implementation follows the SSH-2 protocol standards and provides secure communication using Elliptic Curve Diffie-Hellman key exchange and AES-256-CBC encryption.

## Features

- SSH-2 protocol implementation
- Elliptic Curve Diffie-Hellman key exchange
- RSA Signatures for verifying server identity
- AES-256-CBC encryption with HMAC-SHA256 for integrity
- Basic client and server functionality
- Support for both encrypted and unencrypted communication (for learning purposes)

## Components

The project is structured around the following key components:

1. **TCPPacket Class**: Base class for all packet types
2. **SSHPacket Class**: Specific implementation for SSH protocol packets
3. **NetworkClient/Server**: Basic client/server without encryption
4. **SSHClient/Server**: Adds encryption and key exchange to the base classes
5. **Crypto Library**: Custom implementations of cryptographic primitives

## Building the Project

To build the project, you'll need CMake and a C++17 compliant compiler:

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

After building, you can run the application in different modes:

### Test Mode (Unencrypted)

```bash
./sshctrl demo
```

This will run a simple test that creates an unencrypted server and client, exchanges messages, and then shuts down.

### Server Mode

```bash
./ssh_client_server server
```

This will start an SSH server on port 2222 and wait for client connections.

### Client Mode

```bash
./ssh_client_server client <host> <port>
```

This will connect to an SSH server at the specified host and port. If no host and port is given, it defaults to 127.0.0.1 on port 2222

## Implementation Details

### SSH Protocol Sequence

1. **Protocol Exchange**: Client and server exchange protocol version strings
2. **Key Exchange**:
   - Exchange KEXINIT packets to negotiate algorithms
   - Perform Elliptic Curve Diffie-Hellman key exchange
   - Compute shared secret and session keys
3. **Service Request**: Client requests a service (typically ssh-userauth)
4. **Authentication**: Client authenticates (password, public key, etc.)
5. **Connection**: After successful authentication, client can open channels for terminal sessions, forwarding, etc.

### Security Notes

This implementation is meant for educational purposes and should not be used in production environments. While it implements the core security features of SSH, it may contain vulnerabilities or incomplete implementations of certain aspects of the protocol.

## Educational Value

This project demonstrates:

1. **Network Programming**: Socket programming for client-server communication
2. **Cryptography**: Implementation of cryptographic primitives and protocols
3. **Protocol Design**: Understanding of the SSH protocol
4. **C++ Programming**: Object-oriented design, memory management, etc.

## License

This project is for educational purposes only.
