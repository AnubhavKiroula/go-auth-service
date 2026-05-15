# go-auth-service

A production-style REST API backend written in Go with JWT authentication, bcrypt password hashing, role-based access control, and PostgreSQL.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.21+ |
| Router | [chi v5](https://github.com/go-chi/chi) |
| Database | PostgreSQL |
| DB Driver | [pgx v5](https://github.com/jackc/pgx) |
| Password Hashing | bcrypt (`golang.org/x/crypto/bcrypt`) |
| Authentication | JWT ([golang-jwt/jwt v5](https://github.com/golang-jwt/jwt)) |
| Config | [godotenv](https://github.com/joho/godotenv) |

---

## Prerequisites

- **Go 1.21+** — [Download](https://go.dev/dl/)
- **PostgreSQL 14+** — running locally or accessible via network
- **Git**

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/AnubhavKiroula/go-auth-service.git
cd go-auth-service
```

### 2. Create the `.env` file

Copy the template and fill in your values:

```bash
cp .env.example .env   # or create .env manually
```

`.env` template:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=go_auth_db
JWT_SECRET=your_super_secret_key_change_in_production
PORT=8080
```

> ⚠️ **Never commit `.env` to version control.** It is already in `.gitignore`.

### 3. Create the PostgreSQL database

```sql
-- Run in psql or any PostgreSQL client
CREATE DATABASE go_auth_db;
```

The `users` table and the `pgcrypto` extension are created **automatically** when the app starts.

### 4. Install dependencies

```bash
go mod tidy
```

### 5. Run the application

```bash
go run main.go
```

Expected output:

```
config: database connection pool established
config: database migration applied successfully
Server starting on port 8080
```

---

## API Endpoints

### `POST /signup` — Register a new user

**Auth required:** No

**Request body:**
```json
{
  "name": "Anubhav",
  "email": "anubhav@example.com",
  "password": "secret123",
  "role": "user"
}
```

> `role` accepts `"user"` or `"admin"`. Any other value defaults to `"user"`.

**Response — 201 Created:**
```json
{
  "message": "user created successfully"
}
```

**Error responses:**
| Status | Reason |
|---|---|
| 400 | Missing required fields or password < 6 chars |
| 409 | Email already registered |

---

### `POST /login` — Authenticate and receive a JWT

**Auth required:** No

**Request body:**
```json
{
  "email": "anubhav@example.com",
  "password": "secret123"
}
```

**Response — 200 OK:**
```json
{
  "message": "login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error responses:**
| Status | Reason |
|---|---|
| 400 | Missing email or password |
| 401 | Invalid email or password (same message for both — prevents user enumeration) |

---

### `GET /profile` — Get the authenticated user's profile

**Auth required:** Yes — any role

**Header:**
```
Authorization: Bearer <token>
```

**Response — 200 OK:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Anubhav",
  "email": "anubhav@example.com",
  "role": "user",
  "created_at": "2026-05-15T10:00:00Z"
}
```

**Error responses:**
| Status | Reason |
|---|---|
| 401 | Missing, malformed, or expired JWT |
| 404 | User not found (unlikely unless row was deleted after token was issued) |

---

### `GET /users` — List all users (admin only)

**Auth required:** Yes — role must be `"admin"`

**Header:**
```
Authorization: Bearer <token>
```

**Response — 200 OK:**
```json
{
  "count": 2,
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Anubhav",
      "email": "anubhav@example.com",
      "role": "admin",
      "created_at": "2026-05-15T10:00:00Z"
    },
    {
      "id": "660f9511-f30c-52e5-b827-557766551111",
      "name": "Bob",
      "email": "bob@example.com",
      "role": "user",
      "created_at": "2026-05-15T11:00:00Z"
    }
  ]
}
```

**Error responses:**
| Status | Reason |
|---|---|
| 401 | Missing, malformed, or expired JWT |
| 403 | Valid JWT but role is not `"admin"` |

---

### `GET /health` — Health check

**Auth required:** No

**Response — 200 OK:**
```json
{
  "status": "ok",
  "message": "go-auth-service is running"
}
```

---

## Folder Structure

```
go-auth-service/
├── main.go                  Entry point — wires router, middleware, and routes
├── go.mod                   Module definition and dependency declarations
├── go.sum                   Cryptographic checksums for all dependencies
├── .env                     Local environment variables (never committed)
├── .gitignore               Excludes secrets, binaries, and private docs
├── README.md                This file
├── config/
│   └── db.go                PostgreSQL connection pool + auto-migration
├── models/
│   └── user.go              User struct (PasswordHash excluded from JSON)
├── middleware/
│   └── auth.go              JWT validation middleware + role guard + context helpers
├── handlers/
│   ├── auth.go              Signup and Login handlers
│   └── user.go              GetProfile and ListUsers handlers
└── utils/
    └── jwt.go               JWT generation and parsing utilities
```

---

## Design Decisions

### Why bcrypt?
bcrypt is the industry standard for password hashing. Unlike SHA-256, it is intentionally slow (configurable via cost factor — we use 12) and includes a built-in salt per hash. This makes brute-force and rainbow-table attacks computationally infeasible even if the database is compromised.

### Why JWT?
JWTs are self-contained: the server embeds the user's ID, email, and role directly in the signed token. This means no database lookup is needed to authorise a request — the middleware just verifies the signature and reads the claims. This makes the API horizontally scalable with no shared session state.

### Why PostgreSQL?
PostgreSQL is the most capable open-source relational database available. The `pgcrypto` extension provides `gen_random_uuid()` natively, the `UNIQUE` constraint enforces email uniqueness at the database level (not just the application layer), and `pgx/v5` gives us a high-performance, type-safe driver with connection pooling built in.

### Why chi?
chi is a lightweight, idiomatic router that is fully compatible with `net/http`. It supports middleware grouping, inline middleware with `.With()`, and subrouters — all used in this project. Unlike Gin or Echo, chi adds no non-standard abstractions; every handler is a plain `http.HandlerFunc`.
