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
    stdio: ["ignore", "pipe", "pipe"]
  });
  let serverOutput = "";
  child.stdout.on("data", chunk => { serverOutput += chunk.toString(); });
  child.stderr.on("data", chunk => { serverOutput += chunk.toString(); });
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

  // Exercise consent-enabled live camera signalling end to end at the API layer.
  const liveOfferSdp = "v=0\\r\\n" + "a=sendonly\\r\\n".repeat(6);
  const liveOffer = await api(`/api/sessions/${sessionId}/live-stream`, { token: candidateToken, method: "POST", body: { offerSdp: liveOfferSdp } });
  assert.equal(liveOffer.response.status, 201);
  const liveMonitor = await api("/api/admin/live-streams", { token: adminToken });
  assert.equal(liveMonitor.response.status, 200);
  assert.ok(liveMonitor.data.streams.some(stream => stream.stream_id === liveOffer.data.streamId));
  assert.ok(liveMonitor.data.enabledExams.some(exam => exam.id === examId));
  const liveAnswer = await api(`/api/admin/live-streams/${liveOffer.data.streamId}/answer`, { token: adminToken, method: "POST", body: { answerSdp: "v=0\\r\\n" + "a=recvonly\\r\\n".repeat(6) } });
  assert.equal(liveAnswer.response.status, 200);
  const studentLiveAnswer = await api(`/api/sessions/${sessionId}/live-stream/answer`, { token: candidateToken });
  assert.equal(studentLiveAnswer.response.status, 200);
  assert.equal(studentLiveAnswer.data.status, "connected");

  // Verify a future scheduled test is listed for students but cannot start early,
  // and that the per-exam live monitor switch persists.
  const scheduledCopy = await api(`/api/admin/exams/${examId}/duplicate`, { token: adminToken, method: "POST", body: { title: "Scheduled monitor-off test" } });
  assert.equal(scheduledCopy.response.status, 201);
  const scheduledId = scheduledCopy.data.exam.id;
  const opensAt = new Date(Date.now() + 60_000).toISOString();
  const closesAt = new Date(Date.now() + 3_600_000).toISOString();
  const scheduleSettings = await api(`/api/admin/exams/${scheduledId}`, { token: adminToken, method: "PUT", body: { availableFrom: opensAt, availableUntil: closesAt, liveMonitorEnabled: false, attemptLimit: 1 } });
  assert.equal(scheduleSettings.response.status, 200);
  assert.equal(scheduleSettings.data.live_monitor_enabled, 0);
  const scheduledPublish = await api(`/api/admin/exams/${scheduledId}/publish`, { token: adminToken, method: "POST", body: {} });
  assert.equal(scheduledPublish.response.status, 200);
  const studentExamList = await api("/api/exams", { token: candidateToken });
  assert.equal(studentExamList.response.status, 200);
  const scheduledVisible = studentExamList.data.exams.find(exam => exam.id === scheduledId);
  assert.ok(scheduledVisible, "future scheduled tests should be visible to the assigned student");
  assert.equal(scheduledVisible.live_monitor_enabled, 0);
  const startTooEarly = await api(`/api/exams/${scheduledId}/sessions`, { token: candidateToken, method: "POST", body: {} });
  assert.equal(startTooEarly.response.status, 409);
  assert.match(startTooEarly.data.error, /not available yet/i);

  const savedCorrect = await api(`/api/sessions/${sessionId}/answers`, { token: candidateToken, method: "PUT", body: { questionId: q0.id, selectedIndex: 0, markedReview: false } });
  assert.equal(savedCorrect.response.status, 200, JSON.stringify(savedCorrect.data) + "\\n" + serverOutput);
  const savedWrong = await api(`/api/sessions/${sessionId}/answers`, { token: candidateToken, method: "PUT", body: { questionId: q1.id, selectedIndex: 1, markedReview: true } });
  assert.equal(savedWrong.response.status, 200, JSON.stringify(savedWrong.data) + "\\n" + serverOutput);
  const recovery = await api("/api/student/active-session", { token: candidateToken });
  assert.equal(recovery.response.status, 200);
  assert.equal(recovery.data.active, true);
  assert.equal(recovery.data.session.id, sessionId);
  assert.equal(recovery.data.savedAnswers.length, 2);
  assert.equal(recovery.data.savedAnswers.find(a => a.questionId === q1.id).markedReview, true);
  assert.ok(recovery.data.remainingSeconds > 0);

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

  const duplicate = await api(`/api/admin/exams/${examId}/duplicate`, { token: adminToken, method: "POST", body: { title: "Restricted copied test" } });
  assert.equal(duplicate.response.status, 201);
  assert.equal(duplicate.data.exam.question_count, 180);
  const restrictedId = duplicate.data.exam.id;
  const restrictedSettings = await api(`/api/admin/exams/${restrictedId}`, { token: adminToken, method: "PUT", body: { targetBatch: "Restricted Batch", attemptLimit: 1 } });
  assert.equal(restrictedSettings.response.status, 200);
  assert.equal(restrictedSettings.data.target_batch, "Restricted Batch");
  const restrictedPublish = await api(`/api/admin/exams/${restrictedId}/publish`, { token: adminToken, method: "POST", body: {} });
  assert.equal(restrictedPublish.response.status, 200);
  const notAssigned = await api(`/api/exams/${restrictedId}/sessions`, { token: otherLogin.data.token, method: "POST", body: {} });
  assert.equal(notAssigned.response.status, 403);
  const deletePublishedWithoutAttempts = await api(`/api/admin/exams/${restrictedId}`, { token: adminToken, method: "DELETE" });
  assert.equal(deletePublishedWithoutAttempts.response.status, 200);

  const activeSecond = await api(`/api/exams/${examId}/sessions`, { token: otherLogin.data.token, method: "POST", body: {} });
  assert.equal(activeSecond.response.status, 201);
  const secondSessionId = activeSecond.data.session.id;
  const savedBeforeTerminate = await api(`/api/sessions/${secondSessionId}/answers`, { token: otherLogin.data.token, method: "PUT", body: { questionId: activeSecond.data.questions[0].id, selectedIndex: 0, markedReview: false } });
  assert.equal(savedBeforeTerminate.response.status, 200);
  const terminated = await api(`/api/admin/sessions/${secondSessionId}/terminate`, { token: adminToken, method: "POST", body: { reason: "Integration test termination" } });
  assert.equal(terminated.response.status, 200);
  assert.equal(terminated.data.status, "expired");
  const statusAfterTerminate = await api(`/api/sessions/${secondSessionId}/status`, { token: otherLogin.data.token });
  assert.equal(statusAfterTerminate.response.status, 200);
  assert.equal(statusAfterTerminate.data.terminatedByAdmin, true);
  assert.equal(statusAfterTerminate.data.terminationReason, "Integration test termination");
  const cannotSaveAfterTerminate = await api(`/api/sessions/${secondSessionId}/answers`, { token: otherLogin.data.token, method: "PUT", body: { questionId: activeSecond.data.questions[0].id, selectedIndex: 1, markedReview: false } });
  assert.equal(cannotSaveAfterTerminate.response.status, 409);

  const attemptLimit = await api(`/api/exams/${examId}/sessions`, { token: otherLogin.data.token, method: "POST", body: {} });
  assert.equal(attemptLimit.response.status, 409);
  const results = await api("/api/admin/results", { token: adminToken });
  assert.equal(results.response.status, 200);
  assert.ok(results.data.results.some(r => r.session_id === secondSessionId && r.termination_reason === "Integration test termination"));

  const cannotDeleteWithHistory = await api(`/api/admin/exams/${examId}`, { token: adminToken, method: "DELETE" });
  assert.equal(cannotDeleteWithHistory.response.status, 409);
  const archive = await api(`/api/admin/exams/${examId}/archive`, { token: adminToken, method: "POST", body: {} });
  assert.equal(archive.response.status, 200);

  const scratch = await api("/api/admin/exams", { token: adminToken, method: "POST", body: { title: "Question CRUD draft", durationMinutes: 45 } });
  assert.equal(scratch.response.status, 201);
  const scratchId = scratch.data.exam.id;
  const question = { subject: "Physics", chapter: "Kinematics", difficulty: "easy", prompt: "Manual question?", options: ["A","B","C","D"], answerIndex: 1, explanation: "Because B is correct." };
  const addedQuestion = await api(`/api/admin/exams/${scratchId}/questions`, { token: adminToken, method: "POST", body: { question } });
  assert.equal(addedQuestion.response.status, 201);
  const editedQuestion = await api(`/api/admin/exams/${scratchId}/questions/${addedQuestion.data.questionId}`, { token: adminToken, method: "PUT", body: { question: { ...question, prompt: "Edited question?" } } });
  assert.equal(editedQuestion.response.status, 200);
  const deletedQuestion = await api(`/api/admin/exams/${scratchId}/questions/${addedQuestion.data.questionId}`, { token: adminToken, method: "DELETE" });
  assert.equal(deletedQuestion.response.status, 200);
  const deleteDraft = await api(`/api/admin/exams/${scratchId}`, { token: adminToken, method: "DELETE" });
  assert.equal(deleteDraft.response.status, 200);

  const resetPassword = await api(`/api/admin/students/${secondCandidate.data.user.id}/reset-password`, { token: adminToken, method: "POST", body: { newPassword: "Changed-password-123!" } });
  assert.equal(resetPassword.response.status, 200);
  const loginWithResetPassword = await api("/api/auth/login", { method: "POST", body: { email: "other@example.test", password: "Changed-password-123!" } });
  assert.equal(loginWithResetPassword.response.status, 200);
});
