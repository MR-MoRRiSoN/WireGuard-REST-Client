# WireGuard REST Client

> A lightweight custom REST API for managing WireGuard VPN — built with Spring Boot.

[![Java](https://img.shields.io/badge/Java-Spring%20Boot-6DB33F?style=for-the-badge&logo=spring)](https://spring.io/projects/spring-boot)
[![WireGuard](https://img.shields.io/badge/WireGuard-VPN-88171A?style=for-the-badge&logo=wireguard)](https://www.wireguard.com)
[![Maven](https://img.shields.io/badge/Maven-Build-C71A36?style=for-the-badge&logo=apache-maven)](https://maven.apache.org)

---

## 📋 About

**WireGuard REST Client** is a Spring Boot REST API that wraps WireGuard's CLI into clean HTTP endpoints. Nothing groundbreaking — but if you need a **simple, free, self-hosted solution** to manage WireGuard programmatically without paying for commercial tools like Tailscale or WireGuard Business, this does the job well.

It handles peer creation, session management, time-limited access, and real-time connection monitoring — all over a straightforward REST interface.

---

## ✨ Features

- 🔐 **WireGuard lifecycle control** — start/stop the VPN service via API
- 👥 **Peer management** — create, list, update and remove VPN clients
- ⏱ **Time-limited sessions** — create clients with a session expiry time
- 📊 **Connection monitoring** — see who's connected, how many, and their stats
- 🔑 **Server key access** — retrieve VPN server public data
- 🔒 **Role-based authentication** — secured with Spring Security

---

## 🛠 Tech Stack

| Technology | Usage |
|---|---|
| **Java** | Core language |
| **Spring Boot** | REST API framework |
| **Spring Security** | Authentication & role management |
| **WireGuard** | VPN protocol & tunnel management |
| **Maven** | Build & dependency management |

---

## 📡 API Reference

### Health Check
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/hi` | Health check — returns service greeting |

---

### VPN Service Control
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/vpn/start` | Start the WireGuard service |
| `POST` | `/api/vpn/stop` | Stop the WireGuard service |
| `GET` | `/api/vpn/status` | Get current WireGuard status (`STARTED` / `STOPPED`) |
| `GET` | `/api/vpn/info` | Comprehensive overview — status, total clients, connected clients |

---

### Client Management
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/vpn/clients` | List all configured VPN clients |
| `GET` | `/api/vpn/clients/connected` | List currently connected clients only |
| `GET` | `/api/vpn/clients/detailed` | Detailed peer info for all clients |
| `GET` | `/api/vpn/clients/active-clients-count` | Get count of active connections |
| `POST` | `/api/vpn/create-client` | Create a new VPN client, returns credentials |
| `POST` | `/api/vpn/create-client-with-limited-time/{time}` | Create a client with session expiry (`LocalDateTime`) |
| `PUT` | `/api/vpn/update-vpn-client-limited-time` | Update an existing client's session end time |
| `POST` | `/api/vpn/terminate-vpn-client-session` | Terminate a specific client's active session |

---

### Server Data
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/vpn/get-vpn-server-data` | Retrieve VPN server public key and config data |
| `POST` | `/api/vpn/load-vpn-client-connection-list-data` | Get connection data for a list of client public keys |

---

## 🚀 Getting Started

### Prerequisites

- Java 17+
- Maven 3.8+
- WireGuard installed (`apt install wireguard`)
- Linux / Ubuntu server

### Installation

```bash
git clone https://github.com/MR-MoRRiSoN/WireGuard-REST-Client.git
cd WireGuard-REST-Client
```

### Configuration

```properties
spring.application.name=VpnManager
spring.application.app-manager-user=${APP_MANAGER_USER}
spring.application.app-manager-passwd=${APP_MANAGER_PASSWD}
spring.application.app-manager-role=${APP_MANAGER_ROLE}
ubuntu.sudo.password=${UBUNTU_SUDO_PASSWORD}
server.port=8000
```

### Run

```bash
./mvnw spring-boot:run
```

API available at `http://localhost:8000`

---

## 💡 Why This?

There's nothing revolutionary here. But when you want a **free, self-hosted** alternative to paid WireGuard management tools, and you just need clean HTTP endpoints to automate peer creation and monitor connections — this is a solid, no-frills solution that gets out of your way.

---

## 🔒 Security Note

Never commit real credentials to the repository. Use environment variables or GitHub Actions Secrets for all sensitive configuration.

---

## 📄 License

This project is proprietary. All rights reserved © 2026 WireGuard REST Client.
