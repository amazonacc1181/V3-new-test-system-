# ProctorGuard V3

A standalone CBT platform for NEET-style mock exams. This repository is independent of the legacy ProctorGuard V2 project.

## Features

- Node.js/Express API with SQLite persistence, JWT sessions, bcrypt password hashing, rate limiting, Helmet and configurable CORS.
- Admin candidate creation, exam authoring, question-bank JSON import and strict 180-question validation: Physics 45, Chemistry 45, Biology 90.
- Candidate CBT sessions, per-answer persistence, review flags, +4/−1/0 scoring, reports and answer review.
- Admin dashboard, advisory event timeline, subject/chapter analytics and CSV export.
- Browser interface served by the same Node service at `/`.
- Browser-based face-presence/multiple-face signals are advisory; webcam frames and biometric templates are not sent to the API.

## Local run

Requires Node.js 20+.

1. Run `npm install`.
2. Copy `.env.example` to `.env`.
3. Set `JWT_SECRET` to a unique random secret of at least 32 characters, plus `ADMIN_EMAIL` and `ADMIN_PASSWORD` (at least 12 characters). The server hashes the configured password before checking logins. Alternatively, provide `ADMIN_PASSWORD_HASH`.
4. Keep the admin password only in your hosting provider’s secret environment-variable settings; never commit it to GitHub.
5. Set `DB_PATH=./data/proctorguard.sqlite`.
6. Run `npm start` and open `http://localhost:3000`.

Health check: `GET /api/health`.

## Deployment

Deploy as a Node web service with build command `npm install` and start command `npm start`. Configure `ADMIN_EMAIL` and `ADMIN_PASSWORD` in the host dashboard and point `DB_PATH` to a persistent disk. Do not commit secrets, student data or question banks. Use HTTPS, backups and exact allowed frontend origins. SQLite is for a single instance with persistent storage; use a managed database for multi-instance scale.

## Question bank

Import a JSON array (or `{ "questions": [...] }`) where each item has `subject`, `chapter`, `difficulty`, `prompt`, four `options`, zero-based `answerIndex` (0–3), and `explanation`. Use reviewed, appropriately licensed questions. This app does not fabricate or claim to provide official NEET questions.

## Safety and limitations

Face-presence and multiple-face signals are imperfect and are not identity verification, liveness detection or proof of misconduct. Monitoring events are advisory and must not automatically disqualify candidates. Before real exams, perform end-to-end integration, authorization, backup/restore, accessibility, privacy and load tests.
