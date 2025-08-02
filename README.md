# Zero-Trust Zero-Knowledge File Server

A secure, multi-threaded file server implementation with end-to-end encryption, zero-knowledge architecture, and comprehensive security features.

## Features

### Security
- **Zero-Knowledge Architecture**: Server never has access to unencrypted file contents
- **End-to-End Encryption**: AES-256 for file encryption, RSA-2048 for key exchange
- **Authenticated Encryption**: Optional AES-GCM mode for integrity protection
- **Secure File Deletion**: Multiple-pass overwriting before deletion
- **Password Hashing**: PBKDF2 with SHA-256 (100 iterations)
- **Session Management**: Secure session tokens with configurable TTL
- **Rate Limiting**: Configurable per-client request limits

### Performance
- **Multi-threaded Server**: Handles multiple concurrent clients
- **Connection Pooling**: Efficient resource management
- **Batch Operations**: Support for bulk file uploads/downloads
- **Configurable Thread Pool**: Adjustable worker threads
- **Retry Mechanism**: Automatic retry with exponential backoff

### Features
- **File Sharing**: Share files with other users or groups
- **Access Control Lists**: Fine-grained permission management
- **File Integrity**: SHA-256 checksums for all files
- **Group Management**: Share with multiple users at once
- **Audit Logging**: Comprehensive activity logging

## Architecture

```
===============         ===============         ===============
│   Client    │ <-----> │   Server    │ <-----> │  Storage    │
│             │   TLS   │             │         │             │
│ - Encrypt   │         │ - Multi-    │         │ - Encrypted │
│ - Decrypt   │         │   threaded  │         │   files     │
│ - Hash      │         │ - Zero-     │         │ - Hashed    │
│             │         │   knowledge │         │   names     │
===============         ===============         ===============

```

## Requirements

- Java 11 or higher
- OpenSSL for certificate generation
- JUnit 5 for testing (optional)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd zero-trust-file-server
```

2. Compile the project:
```bash
javac -cp ".:lib/*" -d build src/**/*.java
```

3. Generate certificates (if not already present):
```bash
./scripts/generate_certs.sh
```

## Configuration

The server can be configured through `server.properties` file or environment variables.

### Key Configuration Options

```properties
# Server Configuration
server.port=23068
server.thread.pool.size=10
server.socket.timeout=300000

# SSL Configuration
ssl.protocol=TLSv1.3
ssl.keystore.path=resources/server/server-keystore.p12
ssl.keystore.password=changeit

# Storage Configuration
storage.path=server_data/
storage.max.file.size=104857600

# Security Configuration
security.pbkdf2.iterations=100000
security.session.timeout=3600000
security.max.login.attempts=5

# Rate Limiting
ratelimit.enabled=true
ratelimit.requests.per.minute=60
```

### Environment Variables

Configuration can be overridden using environment variables:
```bash
export FILESERVER_SERVER_PORT=23069
export FILESERVER_SECURITY_SESSION_TIMEOUT=7200000
```

## Usage

### Starting the Server

```bash
java -cp "build:lib/*" server.SSLServer
```

Or with custom configuration:
```bash
java -Dconfig.file=custom.properties -cp "build:lib/*" server.SSLServer
```

### Starting the Client

```bash
java -cp "build:lib/*" client.SSLClient <username> <password>
```

### Client Commands

Once connected, the client supports the following commands:

- **UPLOAD**: Upload a file to the server
- **DOWNLOAD**: Download a file from the server
- **SHARE**: Share a file with another user or group
- **DELETE**: Delete a file from the server
- **REVOKE**: Revoke access from a user
- **QUIT**: Disconnect from the server

### Example Usage

```bash
# Upload a file
Enter Command: UPLOAD
Enter Filename: document.pdf

# Share with another user
Enter Command: SHARE
Enter Filename: document.pdf
Enter username to share with: user2

# Share with a group
Enter Command: SHARE
Enter Filename: document.pdf
Enter username to share with: group1

# Download a shared file
Enter Command: DOWNLOAD
Enter Filename: document.pdf
Enter owner username: user1
```

## Security Considerations

### File Encryption Process

1. **File Upload**:
   - Generate AES-256 key and IV
   - Encrypt file with AES
   - Encrypt AES key and IV with recipient's RSA public key
   - Hash filename with owner credentials
   - Upload encrypted file, key, and IV separately

2. **File Download**:
   - Download encrypted file, key, and IV
   - Decrypt AES key and IV with private RSA key
   - Decrypt file with AES key
   - Verify file integrity with checksum

## Development

### Running Tests

```bash
java -cp "build:lib/*:test-lib/*" org.junit.platform.console.ConsoleLauncher --scan-classpath
```

### Building from Source

```bash
# Clean build
rm -rf build/
mkdir build

# Compile with debug info
javac -g -cp ".:lib/*" -d build src/**/*.java

# Create JAR
jar cf file-server.jar -C build .
```

### Adding New Features

1. Implement feature in appropriate package
2. Add configuration options to `ConfigManager`
3. Update protocol if needed
4. Add comprehensive tests
5. Update documentation

## Monitoring

### Logging

Logs are written to `server.log` and `client_<username>.log` with configurable rotation.

### Metrics

Monitor these key metrics:
- Active connections
- Request rate
- Failed authentication attempts
- Storage usage
- Average response time

## Troubleshooting

### Common Issues

1. **Connection Refused**:
   - Check server is running
   - Verify port is not blocked
   - Check firewall settings

2. **Authentication Failed**:
   - Verify client certificates
   - Check keystore passwords
   - Ensure certificates are not expired

3. **File Not Found**:
   - Check file permissions
   - Verify correct owner specified
   - Ensure file was uploaded successfully

### Debug Mode

Enable debug logging:
```bash
java -Djava.util.logging.level=FINE -cp "build:lib/*" server.SSLServer
```

## Performance Tuning

### Server Optimisation

```properties
# Increase thread pool for high load
server.thread.pool.size=50
server.thread.pool.max=100

# Adjust timeouts
server.socket.timeout=600000
client.timeout=60000

# Enable caching
performance.cache.enabled=true
performance.cache.size=10000
```

### Client Optimisation

- Use batch operations for multiple files
- Enable connection keep-alive
- Implement client-side caching

## License

This project is licensed under the MIT License - see the LICENSE file for details.
