# shadowtunnel
Secure HTTP/HTTPS proxy tunnel with encryption

This library provides a secure tunnel that works as an encrypted HTTP/HTTPS proxy. It allows you to route HTTP and HTTPS traffic through an encrypted connection to bypass censorship or protect your traffic.

## How it works

1. The server runs both an encrypted tunnel server (on port 1234) and an HTTP proxy server (on port 8080)
2. The client connects to the encrypted tunnel and provides a local HTTP proxy (on port 8081)
3. All traffic between client and server is encrypted using Diffie-Hellman key exchange and AES-256-GCM encryption
4. HTTP/HTTPS requests are forwarded through the encrypted tunnel

## Setup

1. Generate keys through `node keygen.mjs`
2. Copy `server_identity.pub` to the client machine
3. Run the server: `node server.mjs`
4. Run the client: `node client.mjs`
5. Configure your browser to use proxy: localhost:8081

## Ports

- Server tunnel: 1234
- Server HTTP proxy: 8080 (currently for internal use - actual proxying happens through the tunnel)
- Client HTTP proxy: 8081