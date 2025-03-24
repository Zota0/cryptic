# Cryptic - Secure Messaging and Transaction Platform

A secure web application built with Go, HTMX, and TailwindCSS that demonstrates secure user authentication, end-to-end encrypted messaging, and transaction management.

## Features

- **Secure User Authentication**
  - Registration and login with Argon2id password hashing
  - JWT-based session management with HS384 signing
  - Salt-based password protection

- **End-to-End Encrypted Messaging**
  - X25519 for key exchange
  - ChaCha20-Poly1305 for message encryption
  - Perfect forward secrecy with ephemeral keys

- **Transaction Management**
  - Balance tracking
  - Transaction history
  - Secure transaction processing

## Security Measures

- Advanced password hashing with Argon2id
- 384-bit JWT tokens
- End-to-end encryption for messages
- Secure key storage
- CORS protection
- Input validation and sanitization

## Development Setup

1. Install dependencies:
   ```bash
   go mod download
   ```

2. Set up MySQL database and update .env file with your database credentials

3. Run the application:
   ```bash
   go run main.go
   ```

## API Endpoints

### Public Routes
- POST /api/register - User registration
- POST /api/login - User authentication

### Protected Routes (Requires JWT)
- POST /api/messages - Send encrypted message
- GET /api/messages - Get received messages
- POST /api/transactions - Create transaction
- GET /api/transactions - Get transaction history
- GET /api/balance - Get current balance

## Security Notice

This is a demonstration project showcasing secure communication and transaction handling. While it implements proper security measures, it should not be used in production without thorough security auditing and hardening.

## License

MIT License