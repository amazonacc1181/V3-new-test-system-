# ProctorGuard V3

A standalone NEET-style CBT prototype with different role-based spaces for students and administrators. The repository is independent of the legacy ProctorGuard V2 project.

## Portal capabilities

- **Student portal:** Overview, lesson-video links, published tests, exam sessions, personal score history, fee balance and account contact details.
- **Administrator portal:** Overview dashboard, student account creation/management, test authoring, JSON question-bank import, preview, publish, draft deletion, archive, fees ledger, lesson links, analytics/CSV reports and active-session monitoring.
- **Exam scheduling:** Multiple exam drafts can be created, each with an optional start date/time, optional end deadline, assigned batch, attempt limit, and an independent live-monitor enabled/disabled setting. Fixed-window tests use both dates; deadline-only tests leave the start blank.
- **Live exam monitor:** For a published exam with monitoring enabled, students who consent to camera/microphone use at exam entry automatically publish a video-only camera feed to the administrator's live monitor. The administrator can filter by exam and open a specific live room. The monitor shows up to 12 simultaneous peer-to-peer camera feeds per administrator browser in this free build.
- **Communication:** Administrator-to-student and broadcast text messages, plus one-to-one or small-group voice/video calls. Students get visible call controls and can mute, disable the camera, or end calls. Calls are available only for exams with monitoring enabled.
- **Session control:** An administrator can terminate an active student's test with a confirmation and optional reason. Saved answers are retained, an audit event is recorded, and the student screen checks the session status and displays a termination notice.
- **CBT:** Per-answer save, review flags, NTA-style question palette, +4/−1/0 scoring, reports, and local advisory face-presence/multiple-face checks.
- **Security baseline:** JWT auth, bcrypt password hashes, rate limiting, Helmet headers, admin-only operations and student-session ownership checks.

## Storage: important

The default SQLite database on a free Render filesystem is **not durable**. It may be lost during a restart/redeploy. Configure the optional encrypted GitHub snapshot feature below before creating real student data.

GitHub snapshots store a **gzip-compressed, AES-256-GCM-encrypted SQLite database** in a separate private data repository. The encryption key and write token belong only in Render environment variables, never in source code. Repository snapshots are not a replacement for a transactional database: writes are batched, each snapshot creates a Git commit, GitHub API limits apply, and restoring older commits is an operational recovery action. This design is suitable only for a low-volume prototype, not a high-stakes school records system.

The database snapshot includes student account details, password hashes, fee records, question banks, answers, scores, reports and monitoring-event metadata. It does not contain stored webcam recordings; live video is transmitted directly between browsers after student approval. Avoid real student data until you have checked access controls, data-handling obligations and recovery.

### Enable encrypted GitHub storage

1. Create a **separate private repository** (for example, `proctorguard-private-data`). Do not use the public V3 source-code repository for plain student records.
2. Create a GitHub fine-grained personal access token restricted to that private data repository, with **Contents: Read and write**. Keep it private.
3. Generate an encryption key containing 32 random bytes, represented as 64 hexadecimal characters, for example with `openssl rand -hex 32`. Save it somewhere private and safe. If it is lost, the snapshots cannot be decrypted.
4. In Render → your V3 web service → Environment, add:
   - `GITHUB_STORAGE_OWNER`: your GitHub username
   - `GITHUB_STORAGE_REPO`: the private data repo name
   - `GITHUB_STORAGE_PATH`: `proctorguard.sqlite.enc.json`
   - `GITHUB_STORAGE_BRANCH`: `main`
   - `GITHUB_STORAGE_TOKEN`: your fine-grained token
   - `GITHUB_STORAGE_ENCRYPTION_KEY`: the 64-character hex key
5. Save changes and let V3 redeploy. The admin portal's data-storage status should report that encrypted GitHub storage is configured. Make a dummy student, then verify a new encrypted snapshot file appears in the private repository before using the portal.

If storage is configured but GitHub cannot restore a snapshot, V3 intentionally fails startup rather than silently starting with a blank database. Keep the token/key secure and rotate them if exposed.

## Local run

Requires Node.js 20+.

1. Run `npm install`.
2. Copy `.env.example` to `.env`.
3. Set `JWT_SECRET` to a random value of at least 32 characters, plus `ADMIN_EMAIL` and `ADMIN_PASSWORD` (at least 12 characters), or provide `ADMIN_PASSWORD_HASH`.
4. Run `npm start` and open `http://localhost:3000`.

## Question bank

Import a JSON array (or an object containing a `questions` array). Each question needs `subject`, `chapter`, `difficulty`, `prompt`, four `options`, zero-based `answerIndex` (0–3), and `explanation`. A NEET-style exam must have exactly 45 Physics, 45 Chemistry and 90 Biology questions. The included bank contains clearly labelled placeholders for software testing only, not real NEET questions.

## Limitations

This is a prototype, not a production exam or school-management system. GitHub snapshot storage is not an ideal operational database; fee records are manual ledger entries and do not accept payments; video lessons are secure URL links rather than an uploaded video-hosting service; and face-presence alerts are imperfect and must not automatically disqualify a student. Camera feeds and calls use browser-to-browser WebRTC. Configure `WEBRTC_TURN_URLS`, `WEBRTC_TURN_USERNAME`, and `WEBRTC_TURN_CREDENTIAL` from a trusted TURN provider in Render to improve connectivity on mobile and restrictive networks; without those settings the app uses STUN only and direct video may fail. TURN credentials are delivered to authenticated browsers, so prefer provider-supported short-lived/restricted credentials and never commit real credentials to GitHub. The 12-feed limit is not suitable for hundreds of simultaneous candidates; large cohorts need a dedicated media server/SFU such as LiveKit or another supported provider. Automated API/CI tests do not replace a two-device camera/microphone test and load test on the deployed Render service. Before a real deployment, perform authorization, backup/restore, privacy, accessibility, security and load testing.
