import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import bcrypt from "bcryptjs";

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  return port;
}

test("end-to-end admin, 180-question CBT, scoring, and report permissions", { timeout: 30000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), "proctorguard-v3-"));
  const port = await freePort();
  const adminEmail = "admin@example.test";
  const adminPassword = "Admin-password-123!";
  const candidatePassword = "Candidate-password-123!";
  const adminHash = await bcrypt.hash(adminPassword, 4);
  const child = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DB_PATH: join(directory, "test.sqlite"),
      JWT_SECRET: "test-only-secret-with-more-than-32-characters",
      ADMIN_EMAIL: adminEmail,
      ADMIN_PASSWORD_HASH: adminHash,
      CORS_ORIGINS: ""
    },
    stdio: "ignore"
  });
  t.after(async () => {
    child.kill("SIGTERM");
    await new Promise(resolve => {
      if (child.exitCode !== null) return resolve();
      child.once("exit", resolve);
      setTimeout(resolve, 1000);
    });
    await rm(directory, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  async function waitForServer() {
    const until = Date.now() + 10000;
    while (Date.now() < until) {
      if (child.exitCode !== null) throw new Error("API server exited before becoming healthy");
      try {
        const response = await fetch(base + "/api/health");
        if (response.ok) return;
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    throw new Error("API server did not become healthy in time");
  }
  async function api(path, { token, method = "GET", body } = {}) {
    const response = await fetch(base + path, {
      method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    const data = response.headers.get("content-type")?.includes("application/json") ? await response.json() : await response.text();
    return { response, data };
  }

  await waitForServer();
  const login = await api("/api/auth/login", { method: "POST", body: { email: adminEmail, password: adminPassword } });
  assert.equal(login.response.status, 200);
  const adminToken = login.data.token;

  const createdCandidate = await api("/api/admin/candidates", { token: adminToken, method: "POST", body: { email: "student@example.test", password: candidatePassword } });
  assert.equal(createdCandidate.response.status, 201);

  const createdExam = await api("/api/admin/exams", { token: adminToken, method: "POST", body: { title: "Integration test mock", durationMinutes: 60 } });
  assert.equal(createdExam.response.status, 201);
  const examId = createdExam.data.exam.id;

  const questions = [];
  for (let i = 0; i < 180; i++) {
    const subject = i < 45 ? "Physics" : i < 90 ? "Chemistry" : "Biology";
    questions.push({
      subject, chapter: "Test chapter", difficulty: "medium",
      prompt: `Integration test question ${i + 1}`,
      options: ["Correct", "Wrong A", "Wrong B", "Wrong C"],
      answerIndex: 0, explanation: "Test explanation"
    });
  }
  const imported = await api(`/api/admin/exams/${examId}/questions/import`, { token: adminToken, method: "POST", body: { questions } });
  assert.equal(imported.response.status, 200);
  assert.deepEqual(imported.data.subjects, { Physics: 45, Chemistry: 45, Biology: 90 });

  const published = await api(`/api/admin/exams/${examId}/publish`, { token: adminToken, method: "POST", body: {} });
  assert.equal(published.response.status, 200);
  assert.equal(published.data.questionCount, 180);

  const candidateLogin = await api("/api/auth/login", { method: "POST", body: { email: "student@example.test", password: candidatePassword } });
  assert.equal(candidateLogin.response.status, 200);
  const candidateToken = candidateLogin.data.token;
  const started = await api(`/api/exams/${examId}/sessions`, { token: candidateToken, method: "POST", body: {} });
  assert.equal(started.response.status, 201);
  assert.equal(started.data.questions.length, 180);
  const sessionId = started.data.session.id;
  const q0 = started.data.questions[0];
  const q1 = started.data.questions[1];

  const savedCorrect = await api(`/api/sessions/${sessionId}/answers`, { token: candidateToken, method: "PUT", body: { questionId: q0.id, selectedIndex: 0, markedReview: false } });
  assert.equal(savedCorrect.response.status, 200);
  const savedWrong = await api(`/api/sessions/${sessionId}/answers`, { token: candidateToken, method: "PUT", body: { questionId: q1.id, selectedIndex: 1, markedReview: true } });
  assert.equal(savedWrong.response.status, 200);

  const submitted = await api(`/api/sessions/${sessionId}/submit`, { token: candidateToken, method: "POST", body: {} });
  assert.equal(submitted.response.status, 200);
  assert.equal(submitted.data.report.totalQuestions, 180);
  assert.equal(submitted.data.report.score, 3);
  assert.equal(submitted.data.report.correct, 1);
  assert.equal(submitted.data.report.wrong, 1);
  assert.equal(submitted.data.report.unattempted, 178);

  const secondCandidate = await api("/api/admin/candidates", { token: adminToken, method: "POST", body: { email: "other@example.test", password: "Other-password-123!" } });
  assert.equal(secondCandidate.response.status, 201);
  const otherLogin = await api("/api/auth/login", { method: "POST", body: { email: "other@example.test", password: "Other-password-123!" } });
  assert.equal(otherLogin.response.status, 200);
  const forbiddenReport = await api(`/api/reports/${sessionId}`, { token: otherLogin.data.token });
  assert.equal(forbiddenReport.response.status, 403);
});
