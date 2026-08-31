# Secure Authentication System

A robust user login, registration, and session management backend system built using Python, Flask, PyJWT, bcrypt, and PostgreSQL.

## Features
- **User Registration**: Secure registration with salted `bcrypt` password hashing.
- **User Authentication**: Login endpoint validating credentials against a PostgreSQL database.
- **Session Management**: Stateless JSON Web Tokens (JWT) for authentication.
- **Protected Middleware**: Custom decorator enforcing JWT verification on protected routes.

## Tech Stack
- **Language**: Python 3.x
- **Framework**: Flask
- **ORM / Database**: Flask-SQLAlchemy & PostgreSQL
- **Security**: PyJWT, bcrypt

## API Endpoints
- `POST /register`: Create a new user account.
- `POST /login`: Authenticate and receive a JWT access token.
- `GET /profile`: Protected route returning current session user info (Requires `Authorization: Bearer <token>`).
