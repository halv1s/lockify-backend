# Lockify Backend — Your Passwords, Your Control

Backend API for Lockify (`https://www.lockify.org`). A minimal, privacy-first service providing authentication, encrypted item storage, sharing, and a relation-based access control model.

## What this backend provides

- Auth: SRP-based password-authenticated login that issues JWTs
- Storage: Items, folders, and workspaces persisted in MongoDB
- Sharing: Secure sharing via relations and RSA-encrypted keys
- Authorization: Relation-based access control (ReBAC) with inheritance

## Security design

- Zero-knowledge: only encrypted blobs are stored server-side
- AES-GCM for data encryption (client-side)
- Argon2id for Master Key derivation (client-side)
- SRP-6a (group 3072 via `fast-srp-hap`) for login
- RSA-OAEP (2048, SHA-256) for sharing per-item/folder keys
- JWT for stateless sessions
- Redis for ephemeral SRP challenges

## Tech stack

- Node.js, TypeScript, Express 5
- MongoDB with Mongoose
- Redis client
- Zod for validation, Helmet/CORS for HTTP hardening
- Jest + ts-jest + mongodb-memory-server for tests
- ESLint + TypeScript ESLint

## Getting started

Prerequisites:

- Node.js ≥ 20
- pnpm (repo pin: `pnpm@10.x`)
- Running MongoDB and Redis instances

Environment:

```bash
PORT=5000
MONGO_URI=mongodb://localhost:27017/lockify
REDIS_URL=redis://localhost:6379
JWT_SECRET=change-me
JWT_EXPIRES_IN=1h
```

Install & run:

```bash
pnpm install
pnpm dev
# http://localhost:5000
```

Healthcheck: `GET /api/healthcheck`

Tests:

```bash
pnpm test      # unit/integration
pnpm test:e2e  # end-to-end flows
```

## Repository layout

- `src/server.ts` — Express app setup and routes
- `src/api/v1/*` — route handlers
- `src/services/*` — business logic (auth, items, folders, workspaces, relations, permissions)
- `src/models/*` — Mongoose schemas
- `src/middlewares/*` — JWT auth, Zod validation
- `src/config/*` — Mongo/Redis connections, config
- `src/types/*` — enums and Express typings
- `docs/lockify.dbml` — database schema

Notes:

- ReBAC namespaces: `users`, `workspaces`, `folders`, `items`
- Relations: `owner`, `admin`, `manager`, `member`, `editor`, `viewer`, `parent`

## License

MIT
