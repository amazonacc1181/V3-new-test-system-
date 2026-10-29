import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "./data/proctorguard.sqlite";
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be set to a random value of at least 32 characters.");
  process.exit(1);
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
  console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH. Never use a default admin password.");
  process.exit(1);
}
fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','candidate')), password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exams (id TEXT PRIMARY KEY, title TEXT NOT NULL, duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 1 AND 600), status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS questions (id TEXT PRIMARY KEY, exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE, subject TEXT NOT NULL, chapter TEXT NOT NULL DEFAULT '', difficulty TEXT NOT NULL DEFAULT 'medium', prompt TEXT NOT NULL, options_json TEXT NOT NULL, answer_index INTEGER NOT NULL CHECK(answer_index BETWEEN 0 AND 3), explanation TEXT NOT NULL DEFAULT '', position INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, exam_id TEXT NOT NULL REFERENCES exams(id), user_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL CHECK(status IN ('in_progress','submitted','expired')), started_at TEXT NOT NULL, submitted_at TEXT, duration_seconds INTEGER NOT NULL DEFAULT 0, score INTEGER, correct_count INTEGER, wrong_count INTEGER, unattempted_count INTEGER, report_json TEXT);
CREATE TABLE IF NOT EXISTS answers (session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, question_id TEXT NOT NULL REFERENCES questions(id), selected_index INTEGER CHECK(selected_index BETWEEN 0 AND 3), marked_review INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY(session_id, question_id));
CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, event_type TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')), detail TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_questions_exam_position ON questions(exam_id, position);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, started_at);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, occurred_at);
`);
const now = () => new Date().toISOString();
const safeUser = u => ({ id: u.id, email: u.email, role: u.role });
const issueToken = u => jwt.sign({ sub: u.id, role: u.role, email: u.email }, JWT_SECRET, { expiresIn: "8h", issuer: "proctorguard" });
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
const origins = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
const corsMiddleware = cors({ origin(origin, cb) { if (!origin || origins.includes(origin)) return cb(null, true); return cb(new Error("Origin not allowed")); }, credentials: false });
app.use((req, res, next) => {
  const origin = req.get("origin");
  const ownOrigin = `${req.protocol}://${req.get("host")}`;
  if (!origin || origin === ownOrigin) return next();
  return corsMiddleware(req, res, next);
});
app.use(express.json({ limit: "2mb" }));
app.use(express.static("public"));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.get("/api/health", (_req, res) => res.json({ ok: true, service: "ProctorGuard API", version: "3.0.0", timestamp: now() }));
function auth(req, res, next) {
  const token = (req.headers.authorization || "").match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try { req.user = jwt.verify(token, JWT_SECRET, { issuer: "proctorguard" }); next(); }
  catch { return res.status(401).json({ error: "Invalid or expired session token" }); }
}
function admin(req, res, next) { if (req.user?.role !== "admin") return res.status(403).json({ error: "Administrator access required" }); next(); }
function validateQuestion(q, i) {
  if (!q || !["Physics","Chemistry","Biology"].includes(q.subject) || typeof q.prompt !== "string" || !q.prompt.trim() || !Array.isArray(q.options) || q.options.length !== 4 || q.options.some(x => typeof x !== "string" || !x.trim()) || !Number.isInteger(q.answerIndex) || q.answerIndex < 0 || q.answerIndex > 3) {
    throw new Error(`Question ${i + 1} must have subject, prompt, four options and answerIndex 0-3.`);
  }
}
function publicQuestion(q) { return { id: q.id, position: q.position, subject: q.subject, chapter: q.chapter, difficulty: q.difficulty, prompt: q.prompt, options: JSON.parse(q.options_json) }; }
const qSelect = "SELECT id, position, subject, chapter, difficulty, prompt, options_json FROM questions WHERE exam_id = ? ORDER BY position";
app.post("/api/auth/login", rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false }), async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user && email === ADMIN_EMAIL) {
    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (ok) {
      const id = randomUUID();
      try { db.prepare("INSERT INTO users(id,email,role,password_hash,created_at) VALUES(?,?,?,?,?)").run(id, ADMIN_EMAIL, "admin", ADMIN_PASSWORD_HASH, now()); } catch {}
      user = db.prepare("SELECT * FROM users WHERE email = ?").get(ADMIN_EMAIL);
    }
  }
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid email or password" });
  res.json({ token: issueToken(user), user: safeUser(user), expiresIn: 28800 });
});
app.get("/api/me", auth, (req, res) => {
  const user = db.prepare("SELECT id,email,role FROM users WHERE id=?").get(req.user.sub);
  if (!user) return res.status(401).json({ error: "Account not found" });
  res.json({ user });
});
app.post("/api/admin/candidates", auth, admin, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) return res.status(400).json({ error: "Provide a valid email and a password of at least 12 characters." });
  const id = randomUUID(), hash = await bcrypt.hash(password, 12);
  try { db.prepare("INSERT INTO users(id,email,role,password_hash,created_at) VALUES(?,?,?,?,?)").run(id,email,"candidate",hash,now()); }
  catch { return res.status(409).json({ error: "An account with this email already exists." }); }
  res.status(201).json({ user: { id,email,role:"candidate" } });
});
app.get("/api/exams", auth, (req, res) => {
  const rows = req.user.role === "admin"
    ? db.prepare("SELECT e.*, (SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) question_count FROM exams e ORDER BY created_at DESC").all()
    : db.prepare("SELECT e.id,e.title,e.duration_minutes,e.status,e.created_at,(SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) question_count FROM exams e WHERE e.status='published' ORDER BY created_at DESC").all();
  res.json({ exams: rows });
});
app.post("/api/admin/exams", auth, admin, (req, res) => {
  const title = String(req.body?.title || "").trim();
  const duration = Number(req.body?.durationMinutes || 180);
  if (!title || title.length > 160 || !Number.isInteger(duration) || duration < 1 || duration > 600) return res.status(400).json({ error: "Title and duration (1–600 minutes) are required." });
  const id = randomUUID(); db.prepare("INSERT INTO exams(id,title,duration_minutes,status,created_at) VALUES(?,?,?,'draft',?)").run(id,title,duration,now());
  res.status(201).json({ exam: { id,title,duration_minutes:duration,status:"draft" } });
});
app.post("/api/admin/exams/:id/questions/import", auth, admin, (req, res) => {
  const exam = db.prepare("SELECT * FROM exams WHERE id=?").get(req.params.id);
  if (!exam) return res.status(404).json({ error: "Exam not found" });
  if (exam.status !== "draft") return res.status(409).json({ error: "Only draft exams can be edited." });
  const qs = req.body?.questions;
  if (!Array.isArray(qs) || qs.length < 1 || qs.length > 5000) return res.status(400).json({ error: "Send questions as a JSON array (1–5000 items)." });
  try { qs.forEach(validateQuestion); } catch (e) { return res.status(400).json({ error: e.message }); }
  const insert = db.prepare("INSERT INTO questions(id,exam_id,subject,chapter,difficulty,prompt,options_json,answer_index,explanation,position,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
  const transaction = db.transaction(items => {
    db.prepare("DELETE FROM questions WHERE exam_id=?").run(exam.id);
    items.forEach((q,i) => insert.run(randomUUID(),exam.id,q.subject,q.chapter || "",q.difficulty || "medium",q.prompt.trim(),JSON.stringify(q.options),q.answerIndex,String(q.explanation || ""),i+1,now()));
  });
  try { transaction(qs); } catch { return res.status(400).json({ error: "Import failed; no partial question bank was saved." }); }
  res.json({ imported: qs.length, examId: exam.id, subjects: { Physics: qs.filter(q=>q.subject==="Physics").length, Chemistry: qs.filter(q=>q.subject==="Chemistry").length, Biology: qs.filter(q=>q.subject==="Biology").length } });
});
app.post("/api/admin/exams/:id/publish", auth, admin, (req, res) => {
  const exam = db.prepare("SELECT * FROM exams WHERE id=?").get(req.params.id);
  if (!exam) return res.status(404).json({ error: "Exam not found" });
  const qs = db.prepare("SELECT subject,COUNT(*) n FROM questions WHERE exam_id=? GROUP BY subject").all(exam.id);
  const counts = Object.fromEntries(qs.map(q=>[q.subject,q.n]));
  const total = qs.reduce((n,q)=>n+q.n,0);
  if (total !== 180 || counts.Physics !== 45 || counts.Chemistry !== 45 || counts.Biology !== 90) return res.status(400).json({ error: "NEET-style exam must contain exactly 180 questions: Physics 45, Chemistry 45, Biology 90.", counts, total });
  db.prepare("UPDATE exams SET status='published' WHERE id=?").run(exam.id);
  res.json({ ok:true, examId:exam.id, questionCount:180, counts });
});
app.post("/api/exams/:id/sessions", auth, (req,res) => {
  const exam = db.prepare("SELECT * FROM exams WHERE id=? AND status='published'").get(req.params.id);
  if (!exam) return res.status(404).json({ error: "Published exam not found" });
  const active = db.prepare("SELECT id FROM sessions WHERE user_id=? AND exam_id=? AND status='in_progress'").get(req.user.sub,exam.id);
  if (active) return res.status(409).json({ error:"An active attempt already exists for this exam.",sessionId:active.id });
  const id=randomUUID(), started=now();
  db.prepare("INSERT INTO sessions(id,exam_id,user_id,status,started_at) VALUES(?,?,?,'in_progress',?)").run(id,exam.id,req.user.sub,started);
  const questions=db.prepare(qSelect).all(exam.id).map(publicQuestion);
  res.status(201).json({ session:{id,examId:exam.id,status:"in_progress",startedAt:started,durationMinutes:exam.duration_minutes},exam:{id:exam.id,title:exam.title,questionCount:questions.length},questions,marking:{correct:4,incorrect:-1,unanswered:0} });
});
function ownedActiveSession(req,res) {
  const session=db.prepare("SELECT * FROM sessions WHERE id=?").get(req.params.id);
  if(!session) { res.status(404).json({error:"Session not found"}); return null; }
  if(req.user.role!=="admin" && session.user_id!==req.user.sub) { res.status(403).json({error:"Session access denied"}); return null; }
  if(session.status!=="in_progress") { res.status(409).json({error:"Session is no longer active"}); return null; }
  return session;
}
app.put("/api/sessions/:id/answers", auth, (req,res) => {
  const s=ownedActiveSession(req,res); if(!s)return;
  const {questionId,selectedIndex,markedReview=false}=req.body||{};
  const q=db.prepare("SELECT id FROM questions WHERE id=? AND exam_id=?").get(questionId,s.exam_id);
  if(!q || !(selectedIndex===null || (Number.isInteger(selectedIndex)&&selectedIndex>=0&&selectedIndex<=3)) || typeof markedReview!=="boolean") return res.status(400).json({error:"Invalid answer payload"});
  db.prepare("INSERT INTO answers(session_id,question_id,selected_index,marked_review,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(session_id,question_id) DO UPDATE SET selected_index=excluded.selected_index,marked_review=excluded.marked_review,updated_at=excluded.updated_at").run(s.id,q.id,selectedIndex,markedReview,now());
  res.json({ok:true,savedAt:now()});
});
app.post("/api/sessions/:id/events", auth, (req,res) => {
  const s=ownedActiveSession(req,res); if(!s)return;
  const {eventType,severity="low",detail=""}=req.body||{};
  const allowed=["face_absent","multiple_faces","identity_uncertain","identity_mismatch_suspected","camera_interrupted","tab_hidden","head_pose_warning","monitoring_started","monitoring_stopped"];
  if(!allowed.includes(eventType)||!["info","low","medium","high"].includes(severity)||typeof detail!=="string"||detail.length>500) return res.status(400).json({error:"Invalid event payload"});
  const id=randomUUID();db.prepare("INSERT INTO events(id,session_id,event_type,severity,detail,occurred_at) VALUES(?,?,?,?,?,?)").run(id,s.id,eventType,severity,detail,now());
  res.status(201).json({ok:true,id});
});
app.post("/api/sessions/:id/submit", auth, (req,res) => {
  const s=ownedActiveSession(req,res); if(!s)return;
  const questions=db.prepare("SELECT * FROM questions WHERE exam_id=? ORDER BY position").all(s.exam_id);
  const answers=db.prepare("SELECT * FROM answers WHERE session_id=?").all(s.id);
  const answerMap=new Map(answers.map(a=>[a.question_id,a]));
  let correct=0,wrong=0;
  const review=questions.map(q=>{const a=answerMap.get(q.id);const selected=a?.selected_index??null;const isCorrect=selected===q.answer_index;if(selected!==null){if(isCorrect)correct++;else wrong++;}return {number:q.position,questionId:q.id,subject:q.subject,chapter:q.chapter,prompt:q.prompt,selectedIndex:selected,selectedAnswer:selected===null?null:JSON.parse(q.options_json)[selected],correctAnswerIndex:q.answer_index,correctAnswer:JSON.parse(q.options_json)[q.answer_index],isCorrect,explanation:q.explanation,markedReview:!!a?.marked_review};});
  const total=questions.length,unattempted=total-correct-wrong,score=correct*4-wrong,started=Date.parse(s.started_at),submitted=now();
  const duration=Math.max(0,Math.round((Date.parse(submitted)-started)/1000));
  const subjectBreakdown={};for(const subject of ["Physics","Chemistry","Biology"]){const rows=review.filter(q=>q.subject===subject);const c=rows.filter(q=>q.isCorrect).length,w=rows.filter(q=>q.selectedIndex!==null&&!q.isCorrect).length,attempted=c+w;subjectBreakdown[subject]={total:rows.length,correct:c,wrong:w,unattempted:rows.length-attempted,score:c*4-w,accuracy:attempted?Math.round(c/attempted*100):0};}
  const events=db.prepare("SELECT event_type,severity,detail,occurred_at FROM events WHERE session_id=? ORDER BY occurred_at").all(s.id);
  const report={app:"ProctorGuard",version:"3.0.0",sessionId:s.id,examId:s.exam_id,candidateId:s.user_id,startedAt:s.started_at,submittedAt:submitted,durationSeconds:duration,totalQuestions:total,maxScore:total*4,score,correct,wrong,unattempted,accuracy:correct+wrong?Math.round(correct/(correct+wrong)*100):0,subjectBreakdown,answers:review,monitoringEvents:events,advisoryOnly:true};
  db.prepare("UPDATE sessions SET status='submitted',submitted_at=?,duration_seconds=?,score=?,correct_count=?,wrong_count=?,unattempted_count=?,report_json=? WHERE id=?").run(submitted,duration,score,correct,wrong,unattempted,JSON.stringify(report),s.id);
  res.json({report});
});
app.get("/api/reports/:id", auth, (req,res) => {
  const s=db.prepare("SELECT * FROM sessions WHERE id=?").get(req.params.id);
  if(!s)return res.status(404).json({error:"Report not found"});
  if(req.user.role!=="admin"&&s.user_id!==req.user.sub)return res.status(403).json({error:"Report access denied"});
  if(!s.report_json)return res.status(409).json({error:"Report is not ready"});
  res.json({report:JSON.parse(s.report_json)});
});
app.get("/api/admin/dashboard", auth, admin, (req,res) => {
  const summary=db.prepare("SELECT COUNT(*) totalSessions, SUM(status='in_progress') activeSessions, SUM(status='submitted') submittedSessions, ROUND(AVG(CASE WHEN status='submitted' THEN score END),1) averageScore FROM sessions").get();
  const recent=db.prepare("SELECT s.id,s.status,s.started_at,s.submitted_at,s.score,s.correct_count,s.wrong_count,s.unattempted_count,u.email candidate,e.title exam FROM sessions s JOIN users u ON u.id=s.user_id JOIN exams e ON e.id=s.exam_id ORDER BY s.started_at DESC LIMIT 100").all();
  const alerts=db.prepare("SELECT ev.id,ev.event_type,ev.severity,ev.detail,ev.occurred_at,s.id session_id,u.email candidate FROM events ev JOIN sessions s ON s.id=ev.session_id JOIN users u ON u.id=s.user_id ORDER BY ev.occurred_at DESC LIMIT 100").all();
  res.json({summary,recentSessions:recent,alerts});
});
app.get("/api/admin/analytics", auth, admin, (req,res) => {
  const bySubject=db.prepare("SELECT q.subject,COUNT(*) answers,SUM(CASE WHEN a.selected_index=q.answer_index THEN 1 ELSE 0 END) correct,SUM(CASE WHEN a.selected_index IS NOT NULL AND a.selected_index!=q.answer_index THEN 1 ELSE 0 END) wrong FROM answers a JOIN questions q ON q.id=a.question_id JOIN sessions s ON s.id=a.session_id WHERE s.status='submitted' GROUP BY q.subject").all();
  const byChapter=db.prepare("SELECT q.subject,q.chapter,COUNT(*) answers,SUM(CASE WHEN a.selected_index=q.answer_index THEN 1 ELSE 0 END) correct FROM answers a JOIN questions q ON q.id=a.question_id JOIN sessions s ON s.id=a.session_id WHERE s.status='submitted' GROUP BY q.subject,q.chapter ORDER BY q.subject,q.chapter").all();
  const scoreTrend=db.prepare("SELECT date(submitted_at) day,ROUND(AVG(score),1) average_score,COUNT(*) attempts FROM sessions WHERE status='submitted' GROUP BY date(submitted_at) ORDER BY day DESC LIMIT 30").all();
  res.json({bySubject:bySubject.map(r=>({...r,accuracy:r.answers?Math.round(r.correct/r.answers*100):0})),byChapter,scoreTrend});
});
app.get("/api/admin/sessions/:id/events", auth, admin, (req,res) => {
  const exists=db.prepare("SELECT id FROM sessions WHERE id=?").get(req.params.id);if(!exists)return res.status(404).json({error:"Session not found"});
  res.json({events:db.prepare("SELECT event_type,severity,detail,occurred_at FROM events WHERE session_id=? ORDER BY occurred_at").all(req.params.id)});
});
app.get("/api/admin/reports/export.csv", auth, admin, (_req,res) => {
  const rows=db.prepare("SELECT s.id session_id,u.email candidate,e.title exam,s.status,s.started_at,s.submitted_at,s.duration_seconds,s.score,s.correct_count,s.wrong_count,s.unattempted_count FROM sessions s JOIN users u ON u.id=s.user_id JOIN exams e ON e.id=s.exam_id ORDER BY s.started_at DESC").all();
  const cell=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  res.type("text/csv").attachment("proctorguard-sessions.csv").send([Object.keys(rows[0]||{session_id:"session_id",candidate:"candidate",exam:"exam",status:"status",started_at:"started_at",submitted_at:"submitted_at",duration_seconds:"duration_seconds",score:"score",correct_count:"correct_count",wrong_count:"wrong_count",unattempted_count:"unattempted_count"}).join(","),...rows.map(r=>Object.values(r).map(cell).join(","))].join("\r\n"));
});
app.use((err,_req,res,_next)=>{ if(err?.message==="Origin not allowed")return res.status(403).json({error:"Origin not allowed"}); console.error(err);res.status(500).json({error:"Internal server error"}); });
app.listen(PORT,"0.0.0.0",()=>console.log(`ProctorGuard API v3 listening on port ${PORT}`));
