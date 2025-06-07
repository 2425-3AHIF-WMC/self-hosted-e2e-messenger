# Self-Hosted End-to-End Messenger

## Team Members

* [**Mark Grünzweil**](https://github.com/m-gruen)
* [**Henry Ladstätter**](https://github.com/HenryLad)
* [**Antonio Subašić**](https://github.com/antoniosubasic)
* [**David Vrhovac**](https://github.com/PlutoTinte06)

## Introduction

This project implements a self-hosted end-to-end encrypted messaging application. Which was built as a part of the WMC course at the HTLBLA Leonding in 2025. The goal of this project was to prove the government wrong and show that if a group of students is able to build something like this, criminals can too.

## Features

* End-to-end encryption for all messages
* Secure cryptographic authentication system using user keypairs
* Self-hosted infrastructure
* User authentication and registration
* Real-time messaging with secure WebSocket connections
* Message persistence
* Cross-platform compatibility

## Architecture

The application is built using a client-server architecture:

* **Frontend**: The user interface that runs on the client device
* **Backend**: The server that handles message routing and storage
* **Database**: The storage system for user data and messages

## Prerequisites

- Node.js (v18 or higher)
- Docker and Docker Compose
- PostgreSQL (if running without Docker)

## Installation

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/2425-3AHIF-WMC/self-hosted-e2e-messenger.git
   cd self-hosted-e2e-messenger
   ```

2. Copy `.env-template` to `.env` and update with your values:
   ```bash
   cp .env-template .env
   ```

3. Start the services:
   ```bash
   docker compose up -d --build
   ```

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/2425-3AHIF-WMC/self-hosted-e2e-messenger.git
   cd self-hosted-e2e-messenger
   ```

2. Copy `.env-template` to `.env` and update with your values:
   ```bash
   cp .env-template .env
   ```

3. Install dependencies and build the backend:
   ```bash
   cd backend
   npm install
   ```

4. Install dependencies and build the frontend:
   ```bash
   cd ../frontend
   npm install
   ```

5. Start the PostgreSQL database and create required tables (see `run` script).

6. Start the backend:
   ```bash
   cd ../backend
   npm run dev
   ```

7. In a separate terminal, start the frontend:
   ```bash
   cd ../frontend
   npm run dev
   ```

## Usage

1. Open your browser and navigate to `http://localhost:8080` (or whichever port you specified in the `.env` file)
2. Register a new account
3. Add contacts and start messaging

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| DB_USER | Database username |
| DB_PASSWORD | Database password |
| DB_NAME | Database name |
| DB_PORT | Database port (typically 5432 for PostgreSQL) |
| BACKEND_PORT | Port for the backend server |
| FRONTEND_PORT | Port for the frontend server |

## Security Considerations

- End-to-end encryption ensures that messages can only be read by the intended recipient.
- Authentication is handled through cryptographic signatures using the user's keypair.
  - See [Crypto Authentication System](docs/crypto-auth.md) for details.
- Each authenticated request is individually signed by the user's private key and verified by the server.
- No tokens are used in the authentication process, eliminating the risk of token theft and replay attacks.
- The server generates new cryptographic keys on each restart.
- Timestamps in authentication payloads prevent replay attacks.
- Private keys are generated client-side and never transmitted to the server.
