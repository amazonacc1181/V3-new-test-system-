import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import { randomUUID, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "./data/proctorguard.sqlite";
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || (ADMIN_PASSWORD.length >= 12 ? bcrypt.hashSync(ADMIN_PASSWORD, 12) : "");
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be set to a random value of at least 32 characters.");
  process.exit(1);
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
  console.error("Set ADMIN_EMAIL and either ADMIN_PASSWORD (12+ characters) or ADMIN_PASSWORD_HASH. Never use a default admin password.");
  process.exit(1);
}

const GH_OWNER=process.env.GITHUB_STORAGE_OWNER||"", GH_REPO=process.env.GITHUB_STORAGE_REPO||"", GH_PATH=process.env.GITHUB_STORAGE_PATH||"proctorguard.sqlite.enc.json", GH_BRANCH=process.env.GITHUB_STORAGE_BRANCH||"main", GH_TOKEN=process.env.GITHUB_STORAGE_TOKEN||"", GH_KEY_HEX=process.env.GITHUB_STORAGE_ENCRYPTION_KEY||"";
const ghStorageEnabled=Boolean(GH_OWNER&&GH_REPO&&GH_TOKEN&&/^[a-fA-F0-9]{64}$/.test(GH_KEY_HEX));
const ghKey=ghStorageEnabled?Buffer.from(GH_KEY_HEX,"hex"):null;
let lastGitHubBackupAt=null,lastGitHubBackupError=null,backupTimer=null,backupQueue=Promise.resolve();
function ghHeaders(){return {Authorization:"Bearer "+GH_TOKEN,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"ProctorGuard-V3"}}
function ghUrl(withRef=true){return "https://api.github.com/repos/"+encodeURIComponent(GH_OWNER)+"/"+encodeURIComponent(GH_REPO)+"/contents/"+GH_PATH.split("/").map(encodeURIComponent).join("/")+(withRef?"?ref="+encodeURIComponent(GH_BRANCH):"")}
function encryptSnapshot(input){const iv=randomBytes(12),c=createCipheriv("aes-256-gcm",ghKey,iv),data=Buffer.concat([c.update(gzipSync(input)),c.final()]);return JSON.stringify({v:2,iv:iv.toString("base64"),tag:c.getAuthTag().toString("base64"),data:data.toString("base64")})}
function decryptSnapshot(value){const x=JSON.parse(value);if(![1,2].includes(x.v))throw new Error("Unknown snapshot version");const d=createDecipheriv("aes-256-gcm",ghKey,Buffer.from(x.iv,"base64"));d.setAuthTag(Buffer.from(x.tag,"base64"));const plain=Buffer.concat([d.update(Buffer.from(x.data,"base64")),d.final()]);return x.v===2?gunzipSync(plain):plain}
async function restoreGitHubSnapshot(){
 if(!ghStorageEnabled){console.warn("GitHub encrypted persistence not configured; Render local storage may be ephemeral.");return}
 const r=await fetch(ghUrl(),{headers:ghHeaders()});
 if(r.status===404){console.log("No snapshot exists yet; starting a new database.");return}
 if(!r.ok)throw new Error("GitHub snapshot restore failed HTTP "+r.status+"; check storage repository/token.");
 const doc=await r.json();if(!doc.content)throw new Error("GitHub snapshot content missing.");
 const bytes=decryptSnapshot(Buffer.from(doc.content.replace(/\n/g,""),"base64").toString("utf8"));
 fs.mkdirSync(path.dirname(path.resolve(DB_PATH)),{recursive:true});for(const suffix of ["-wal","-shm"])try{fs.rmSync(path.resolve(DB_PATH)+suffix,{force:true})}catch{}fs.writeFileSync(path.resolve(DB_PATH),bytes);
 lastGitHubBackupAt=doc.commit?.commit?.author?.date||null;console.log("Restored encrypted database from private GitHub repository.");
}
async function saveGitHubSnapshot(){
 if(!ghStorageEnabled)return;
 backupQueue=backupQueue.then(async()=>{
  db.pragma("wal_checkpoint(TRUNCATE)");
  const encrypted=encryptSnapshot(fs.readFileSync(path.resolve(DB_PATH)));
  const current=await fetch(ghUrl(),{headers:ghHeaders()});let sha;
  if(current.ok)sha=(await current.json()).sha;else if(current.status!==404)throw new Error("Snapshot lookup failed HTTP "+current.status);
  const r=await fetch(ghUrl(false),{method:"PUT",headers:{...ghHeaders(),"Content-Type":"application/json"},body:JSON.stringify({message:"Update encrypted ProctorGuard V3 data snapshot",content:Buffer.from(encrypted).toString("base64"),branch:GH_BRANCH,...(sha?{sha}:{})})});
  if(!r.ok)throw new Error("Snapshot write failed HTTP "+r.status+": "+(await r.text()).slice(0,250));
  const result=await r.json();lastGitHubBackupAt=result.commit?.committer?.date||new Date().toISOString();lastGitHubBackupError=null;console.log("Encrypted database snapshot saved to GitHub.");
 }).catch(e=>{lastGitHubBackupError=String(e.message||e);console.error("GitHub snapshot failed:",lastGitHubBackupError)});
 return backupQueue;
}
function scheduleGitHubBackup(){if(!ghStorageEnabled)return;clearTimeout(backupTimer);backupTimer=setTimeout(()=>{saveGitHubSnapshot()},3000)}

fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
if(ghStorageEnabled) await restoreGitHubSnapshot().catch(e=>{console.error(e.message);process.exit(1)});
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','candidate')), password_hash TEXT NOT NULL, created_at TEXT NOT NULL, full_name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', batch TEXT NOT NULL DEFAULT 'General', guardian_contact TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS exams (id TEXT PRIMARY KEY, title TEXT NOT NULL, duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 1 AND 600), status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')), created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS questions (id TEXT PRIMARY KEY, exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE, subject TEXT NOT NULL, chapter TEXT NOT NULL DEFAULT '', difficulty TEXT NOT NULL DEFAULT 'medium', prompt TEXT NOT NULL, options_json TEXT NOT NULL, answer_index INTEGER NOT NULL CHECK(answer_index BETWEEN 0 AND 3), explanation TEXT NOT NULL DEFAULT '', position INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, exam_id TEXT NOT NULL REFERENCES exams(id), user_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL CHECK(status IN ('in_progress','submitted','expired')), started_at TEXT NOT NULL, submitted_at TEXT, duration_seconds INTEGER NOT NULL DEFAULT 0, score INTEGER, correct_count INTEGER, wrong_count INTEGER, unattempted_count INTEGER, report_json TEXT);
CREATE TABLE IF NOT EXISTS answers (session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, question_id TEXT NOT NULL REFERENCES questions(id), selected_index INTEGER CHECK(selected_index BETWEEN 0 AND 3), marked_review INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY(session_id, question_id));
CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, event_type TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')), detail TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_questions_exam_position ON questions(exam_id, position);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, started_at);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, occurred_at);
CREATE TABLE IF NOT EXISTS student_fees (user_id TEXT PRIMARY KEY REFERENCES users(id), amount_due INTEGER NOT NULL DEFAULT 0, amount_paid INTEGER NOT NULL DEFAULT 0, due_date TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS videos (id TEXT PRIMARY KEY, title TEXT NOT NULL, subject TEXT NOT NULL DEFAULT 'General', description TEXT NOT NULL DEFAULT '', url TEXT NOT NULL, batch TEXT NOT NULL DEFAULT 'All batches', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS live_offers (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, admin_id TEXT NOT NULL REFERENCES users(id), offer_sdp TEXT NOT NULL, answer_sdp TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'video');
CREATE TABLE IF NOT EXISTS student_live_streams (id TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE, student_id TEXT NOT NULL REFERENCES users(id), offer_sdp TEXT NOT NULL, answer_sdp TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, answered_at TEXT);
CREATE TABLE IF NOT EXISTS chat_messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT NOT NULL);
`);

const examColumns=new Set(db.prepare("PRAGMA table_info(exams)").all().map(c=>c.name));
for(const [n,d] of [["target_batch","TEXT NOT NULL DEFAULT 'All batches'"],["available_from","TEXT NOT NULL DEFAULT ''"],["available_until","TEXT NOT NULL DEFAULT ''"],["attempt_limit","INTEGER NOT NULL DEFAULT 1"],["live_monitor_enabled","INTEGER NOT NULL DEFAULT 1"]])if(!examColumns.has(n))db.exec("ALTER TABLE exams ADD COLUMN "+n+" "+d);
const userColumns=new Set(db.prepare("PRAGMA table_info(users)").all().map(c=>c.name));
const liveOfferColumns=new Set(db.prepare("PRAGMA table_info(live_offers)").all().map(c=>c.name));
if(!liveOfferColumns.has("mode"))db.exec("ALTER TABLE live_offers ADD COLUMN mode TEXT NOT NULL DEFAULT 'video'");
for(const [n,d] of [["full_name","TEXT NOT NULL DEFAULT ''"],["phone","TEXT NOT NULL DEFAULT ''"],["batch","TEXT NOT NULL DEFAULT 'General'"],["guardian_contact","TEXT NOT NULL DEFAULT ''"],["active","INTEGER NOT NULL DEFAULT 1"]])if(!userColumns.has(n))db.exec("ALTER TABLE users ADD COLUMN "+n+" "+d);
const now = () => new Date().toISOString();
const safeUser = u => ({ id:u.id,email:u.email,role:u.role,fullName:u.full_name||"",phone:u.phone||"",batch:u.batch||"General",guardianContact:u.guardian_contact||"",active:u.active!==0 });
const issueToken = u => jwt.sign({ sub: u.id, role: u.role, email: u.email }, JWT_SECRET, { expiresIn: "8h", issuer: "proctorguard" });
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
    connectSrc: ["'self'", "https://justadudewhohacks.github.io"],
    imgSrc: ["'self'", "data:", "blob:"],
    mediaSrc: ["'self'", "blob:"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    fontSrc: ["'self'", "data:"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: ["'none'"]
  } }
}));
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
app.use((req,res,next)=>{res.on("finish",()=>{if(req.originalUrl.startsWith("/api/")&&["POST","PUT","PATCH","DELETE"].includes(req.method)&&res.statusCode<400)scheduleGitHubBackup()});next()});
app.get("/api/health", (_req,res)=>res.json({ok:true,service:"ProctorGuard API",version:"3.2.0",timestamp:now(),githubStorage:{configured:ghStorageEnabled,lastBackupAt:lastGitHubBackupAt,backupError:lastGitHubBackupError}}));
function auth(req, res, next) {
  const token = (req.headers.authorization || "").match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try { req.user = jwt.verify(token, JWT_SECRET, { issuer: "proctorguard" }); const current=db.prepare("SELECT active,role FROM users WHERE id=?").get(req.user.sub); if(!current||current.active===0||current.role!==req.user.role)return res.status(401).json({error:"Account inactive or session expired"}); next(); }
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
  if (!user || user.active===0 || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid email or password" });
  res.json({ token: issueToken(user), user: safeUser(user), expiresIn: 28800 });
});
app.get("/api/me", auth, (req, res) => {
  const user = db.prepare("SELECT id,email,role FROM users WHERE id=?").get(req.user.sub);
  if (!user) return res.status(401).json({ error: "Account not found" });
  res.json({ user });
});
app.post("/api/admin/candidates", auth, admin, async (req,res)=>{
 const email=String(req.body?.email||"").trim().toLowerCase(),password=String(req.body?.password||"");
 const fullName=String(req.body?.fullName||"").trim().slice(0,120),phone=String(req.body?.phone||"").trim().slice(0,40),batch=String(req.body?.batch||"General").trim().slice(0,80)||"General",guardian=String(req.body?.guardianContact||"").trim().slice(0,80);
 const due=Number(req.body?.amountDue||0),paid=Number(req.body?.amountPaid||0),date=String(req.body?.dueDate||"").slice(0,10);
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<12)return res.status(400).json({error:"Provide a valid email and password of at least 12 characters."});
 if(!Number.isSafeInteger(due)||!Number.isSafeInteger(paid)||due<0||paid<0||paid>due)return res.status(400).json({error:"Fee amounts must be non-negative whole rupee amounts; paid cannot exceed due."});
 const id=randomUUID(),hash=await bcrypt.hash(password,12);
 try{db.transaction(()=>{db.prepare("INSERT INTO users(id,email,role,password_hash,created_at,full_name,phone,batch,guardian_contact) VALUES(?,?,?,?,?,?,?,?,?)").run(id,email,"candidate",hash,now(),fullName,phone,batch,guardian);db.prepare("INSERT INTO student_fees(user_id,amount_due,amount_paid,due_date,note,updated_at) VALUES(?,?,?,?,?,?)").run(id,due,paid,date,"",now())})();}catch{return res.status(409).json({error:"An account with this email already exists."})}
 res.status(201).json({user:{id,email,role:"candidate",fullName,phone,batch,guardianContact:guardian}});
});

app.post("/api/admin/students/:id/reset-password",auth,admin,async(req,res)=>{
 const password=String(req.body?.newPassword||"");
 if(password.length<12||password.length>200)return res.status(400).json({error:"Temporary password must be at least 12 characters."});
 const user=db.prepare("SELECT id,email FROM users WHERE id=? AND role='candidate'").get(req.params.id);
 if(!user)return res.status(404).json({error:"Student not found"});
 const hash=await bcrypt.hash(password,12);db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,user.id);
 res.json({ok:true,email:user.email});
});
app.get("/api/admin/students",auth,admin,(req,res)=>{
 const students=db.prepare("SELECT u.id,u.email,u.full_name,u.phone,u.batch,u.guardian_contact,u.active,u.created_at,COALESCE(f.amount_due,0) amount_due,COALESCE(f.amount_paid,0) amount_paid,COALESCE(f.due_date,'') due_date,COALESCE(f.note,'') fee_note,COUNT(DISTINCT s.id) attempts,MAX(s.submitted_at) last_attempt FROM users u LEFT JOIN student_fees f ON f.user_id=u.id LEFT JOIN sessions s ON s.user_id=u.id WHERE u.role='candidate' GROUP BY u.id ORDER BY u.created_at DESC").all();
 res.json({students});
});
app.put("/api/admin/students/:id",auth,admin,(req,res)=>{
 const u=db.prepare("SELECT id FROM users WHERE id=? AND role='candidate'").get(req.params.id);if(!u)return res.status(404).json({error:"Student not found"});
 const name=String(req.body?.fullName||"").trim().slice(0,120),phone=String(req.body?.phone||"").trim().slice(0,40),batch=String(req.body?.batch||"General").trim().slice(0,80)||"General",guardian=String(req.body?.guardianContact||"").trim().slice(0,80),active=req.body?.active===false?0:1;
 db.prepare("UPDATE users SET full_name=?,phone=?,batch=?,guardian_contact=?,active=? WHERE id=?").run(name,phone,batch,guardian,active,u.id);res.json({ok:true});
});
app.get("/api/account/profile",auth,(req,res)=>{const profile=db.prepare("SELECT id,email,role,full_name,phone,batch,guardian_contact,created_at FROM users WHERE id=?").get(req.user.sub);if(!profile)return res.status(404).json({error:"Account not found"});res.json({profile})});
app.put("/api/account/profile",auth,(req,res)=>{db.prepare("UPDATE users SET phone=?,guardian_contact=? WHERE id=?").run(String(req.body?.phone||"").trim().slice(0,40),String(req.body?.guardianContact||"").trim().slice(0,80),req.user.sub);res.json({ok:true})});
app.post("/api/account/password",auth,async(req,res)=>{
 const current=String(req.body?.currentPassword||""),next=String(req.body?.newPassword||"");
 if(next.length<12||next.length>200)return res.status(400).json({error:"New password must be at least 12 characters."});
 const row=db.prepare("SELECT password_hash FROM users WHERE id=?").get(req.user.sub);
 if(!row||!(await bcrypt.compare(current,row.password_hash)))return res.status(401).json({error:"Current password is incorrect."});
 const hash=await bcrypt.hash(next,12);db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,req.user.sub);res.json({ok:true,message:"Password changed. Sign in again with the new password after this session expires."});
});
app.get("/api/student/fees",auth,(req,res)=>{const fees=db.prepare("SELECT amount_due,amount_paid,due_date,note,updated_at FROM student_fees WHERE user_id=?").get(req.user.sub)||{amount_due:0,amount_paid:0,due_date:"",note:""};res.json({fees})});
app.get("/api/admin/fees",auth,admin,(req,res)=>{res.json({fees:db.prepare("SELECT u.id user_id,u.email,u.full_name,u.batch,COALESCE(f.amount_due,0) amount_due,COALESCE(f.amount_paid,0) amount_paid,COALESCE(f.due_date,'') due_date,COALESCE(f.note,'') note FROM users u LEFT JOIN student_fees f ON f.user_id=u.id WHERE u.role='candidate' ORDER BY u.created_at DESC").all()})});
app.put("/api/admin/fees/:userId",auth,admin,(req,res)=>{
 const u=db.prepare("SELECT id FROM users WHERE id=? AND role='candidate'").get(req.params.userId);if(!u)return res.status(404).json({error:"Student not found"});
 const due=Number(req.body?.amountDue),paid=Number(req.body?.amountPaid),date=String(req.body?.dueDate||"").slice(0,10),note=String(req.body?.note||"").trim().slice(0,500);
 if(!Number.isSafeInteger(due)||!Number.isSafeInteger(paid)||due<0||paid<0||paid>due)return res.status(400).json({error:"Fee amounts must be non-negative whole rupee amounts; paid cannot exceed due."});
 db.prepare("INSERT INTO student_fees(user_id,amount_due,amount_paid,due_date,note,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET amount_due=excluded.amount_due,amount_paid=excluded.amount_paid,due_date=excluded.due_date,note=excluded.note,updated_at=excluded.updated_at").run(u.id,due,paid,date,note,now());res.json({ok:true,outstanding:due-paid});
});
app.get("/api/videos",auth,(req,res)=>{const batch=db.prepare("SELECT batch FROM users WHERE id=?").get(req.user.sub)?.batch||"General";const rows=req.user.role==="admin"?db.prepare("SELECT * FROM videos ORDER BY created_at DESC").all():db.prepare("SELECT * FROM videos WHERE batch='All batches' OR batch=? ORDER BY created_at DESC").all(batch);res.json({videos:rows})});
app.post("/api/admin/videos",auth,admin,(req,res)=>{
 const title=String(req.body?.title||"").trim().slice(0,160),subject=String(req.body?.subject||"General").trim().slice(0,80),description=String(req.body?.description||"").trim().slice(0,1000),url=String(req.body?.url||"").trim(),batch=String(req.body?.batch||"All batches").trim().slice(0,80)||"All batches";
 try{if(new URL(url).protocol!=="https:")throw new Error()}catch{return res.status(400).json({error:"Video URL must be a valid HTTPS link."})}
 if(!title)return res.status(400).json({error:"Video title is required."});
 const id=randomUUID();db.prepare("INSERT INTO videos(id,title,subject,description,url,batch,created_at) VALUES(?,?,?,?,?,?,?)").run(id,title,subject,description,url,batch,now());res.status(201).json({video:{id,title,subject,description,url,batch}});
});
app.delete("/api/admin/videos/:id",auth,admin,(req,res)=>{const r=db.prepare("DELETE FROM videos WHERE id=?").run(req.params.id);if(!r.changes)return res.status(404).json({error:"Video not found"});res.json({ok:true})});
app.get("/api/student/analysis",auth,(req,res)=>{res.json({sessions:db.prepare("SELECT s.id,s.status,s.started_at,s.submitted_at,s.duration_seconds,s.score,s.correct_count,s.wrong_count,s.unattempted_count,e.title exam_title FROM sessions s JOIN exams e ON e.id=s.exam_id WHERE s.user_id=? ORDER BY s.started_at DESC LIMIT 100").all(req.user.sub)})});
app.post("/api/admin/live/:sessionId/offers",auth,admin,(req,res)=>{
 const session=db.prepare("SELECT s.id,s.status,e.live_monitor_enabled FROM sessions s JOIN exams e ON e.id=s.exam_id WHERE s.id=?").get(req.params.sessionId);if(!session||session.status!=="in_progress")return res.status(404).json({error:"Active session not found"});if(!session.live_monitor_enabled)return res.status(403).json({error:"Live calls are disabled for this exam."});
 const sdp=String(req.body?.offerSdp||"");if(sdp.length<20||sdp.length>200000)return res.status(400).json({error:"Invalid WebRTC offer."});
 const mode=req.body?.mode==="voice"?"voice":"video";
 const id=randomUUID();db.prepare("INSERT INTO live_offers(id,session_id,admin_id,offer_sdp,status,created_at,mode) VALUES(?,?,?,?,'pending',?,?)").run(id,session.id,req.user.sub,sdp,now(),mode);res.status(201).json({offerId:id,mode});
});
app.get("/api/admin/live/:sessionId/offers/:offerId/answer",auth,admin,(req,res)=>{
 const row=db.prepare("SELECT id,status,answer_sdp,created_at,mode FROM live_offers WHERE id=? AND session_id=? AND admin_id=?").get(req.params.offerId,req.params.sessionId,req.user.sub);
 if(!row)return res.status(404).json({error:"Live video request not found"});res.json({offer:row});
});
app.get("/api/sessions/:id/live-offers",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status FROM sessions WHERE id=?").get(req.params.id);
 if(!session||session.user_id!==req.user.sub||session.status!=="in_progress")return res.status(404).json({error:"Active student session not found"});
 const offers=db.prepare("SELECT id,offer_sdp,created_at,mode FROM live_offers WHERE session_id=? AND status='pending' AND created_at>=? ORDER BY created_at").all(session.id,new Date(Date.now()-5*60*1000).toISOString());
 res.json({offers});
});
app.post("/api/sessions/:id/live-offers/:offerId/answer",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status FROM sessions WHERE id=?").get(req.params.id);
 if(!session||session.user_id!==req.user.sub||session.status!=="in_progress")return res.status(404).json({error:"Active student session not found"});
 const offer=db.prepare("SELECT id,status FROM live_offers WHERE id=? AND session_id=?").get(req.params.offerId,session.id);if(!offer)return res.status(404).json({error:"Live video request not found"});
 if(req.body?.declined===true){db.prepare("UPDATE live_offers SET status='declined' WHERE id=? AND status='pending'").run(offer.id);return res.json({ok:true,status:"declined"})}
 const sdp=String(req.body?.answerSdp||"");if(sdp.length<20||sdp.length>200000)return res.status(400).json({error:"Invalid WebRTC answer."});
 db.prepare("UPDATE live_offers SET answer_sdp=?,status='accepted' WHERE id=? AND status='pending'").run(sdp,offer.id);res.json({ok:true,status:"accepted"});
});
app.get("/api/sessions/:id/status",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status,submitted_at FROM sessions WHERE id=?").get(req.params.id);
 if(!session)return res.status(404).json({error:"Session not found"});
 if(req.user.role!=="admin"&&session.user_id!==req.user.sub)return res.status(403).json({error:"Session access denied"});
 const termination=db.prepare("SELECT detail,occurred_at FROM events WHERE session_id=? AND event_type='admin_terminated' ORDER BY occurred_at DESC LIMIT 1").get(session.id);
 res.json({sessionId:session.id,status:session.status,submittedAt:session.submitted_at,terminatedByAdmin:Boolean(termination&&session.status==="expired"),terminationReason:termination?.detail||""});
});
app.post("/api/admin/sessions/:id/terminate",auth,admin,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status,started_at FROM sessions WHERE id=?").get(req.params.id);
 if(!session)return res.status(404).json({error:"Session not found"});
 if(session.status!=="in_progress")return res.status(409).json({error:"This session is no longer active."});
 const reason=String(req.body?.reason||"Terminated by administrator").trim().slice(0,300)||"Terminated by administrator";
 const ended=now(),duration=Math.max(0,Math.round((Date.parse(ended)-Date.parse(session.started_at))/1000));
 const terminate=db.transaction(()=>{
  const result=db.prepare("UPDATE sessions SET status='expired',submitted_at=?,duration_seconds=? WHERE id=? AND status='in_progress'").run(ended,duration,session.id);
  if(!result.changes)throw new Error("This session is no longer active.");
  db.prepare("INSERT INTO events(id,session_id,event_type,severity,detail,occurred_at) VALUES(?,?,?,'medium',?,?)").run(randomUUID(),session.id,"admin_terminated",reason,ended);
  db.prepare("UPDATE live_offers SET status='declined' WHERE session_id=? AND status='pending'").run(session.id);
  db.prepare("UPDATE student_live_streams SET status='ended' WHERE session_id=?").run(session.id);
 });
 try{terminate()}catch(e){return res.status(409).json({error:e.message||"Could not terminate session."})}
 res.json({ok:true,sessionId:session.id,status:"expired",terminatedAt:ended,reason});
});

app.post("/api/sessions/:id/live-stream",auth,(req,res)=>{
 const session=db.prepare("SELECT s.id,s.user_id,s.status,e.live_monitor_enabled FROM sessions s JOIN exams e ON e.id=s.exam_id WHERE s.id=?").get(req.params.id);
 if(!session||session.user_id!==req.user.sub||session.status!=="in_progress")return res.status(404).json({error:"Active student session not found"});
 if(!session.live_monitor_enabled)return res.status(403).json({error:"Live monitoring is disabled for this exam."});
 const sdp=String(req.body?.offerSdp||"");if(sdp.length<20||sdp.length>200000)return res.status(400).json({error:"Invalid live stream offer."});
 const id=randomUUID(),created=now();
 db.prepare("INSERT INTO student_live_streams(id,session_id,student_id,offer_sdp,status,created_at) VALUES(?,?,?,?,'pending',?) ON CONFLICT(session_id) DO UPDATE SET id=excluded.id,student_id=excluded.student_id,offer_sdp=excluded.offer_sdp,answer_sdp=NULL,status='pending',created_at=excluded.created_at,answered_at=NULL").run(id,session.id,req.user.sub,sdp,created);
 res.status(201).json({streamId:id,status:"pending"});
});
app.get("/api/sessions/:id/live-stream/answer",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status FROM sessions WHERE id=?").get(req.params.id);
 if(!session||session.user_id!==req.user.sub)return res.status(404).json({error:"Student session not found"});
 const stream=db.prepare("SELECT id,status,answer_sdp,created_at FROM student_live_streams WHERE session_id=?").get(session.id);
 if(!stream)return res.json({status:"not_started"});
 res.json({streamId:stream.id,status:stream.status,answerSdp:stream.answer_sdp,createdAt:stream.created_at});
});
app.get("/api/admin/live-streams",auth,admin,(req,res)=>{
 const streams=db.prepare("SELECT st.id stream_id,st.session_id,st.offer_sdp,st.answer_sdp,st.status stream_status,st.created_at,u.email,u.full_name,u.batch,e.id exam_id,e.title exam_title,e.live_monitor_enabled,s.started_at FROM student_live_streams st JOIN sessions s ON s.id=st.session_id JOIN users u ON u.id=st.student_id JOIN exams e ON e.id=s.exam_id WHERE s.status='in_progress' AND e.live_monitor_enabled=1 AND st.created_at>=? ORDER BY st.created_at").all(new Date(Date.now()-12*60*60*1000).toISOString());
 const enabledExams=db.prepare("SELECT e.id,e.title,e.status,e.available_from,e.available_until,(SELECT COUNT(*) FROM sessions s WHERE s.exam_id=e.id AND s.status='in_progress') active_count FROM exams e WHERE e.status='published' AND e.live_monitor_enabled=1 ORDER BY e.created_at DESC").all();
 res.json({streams,enabledExams});
});
app.post("/api/admin/live-streams/:id/answer",auth,admin,(req,res)=>{
 const stream=db.prepare("SELECT st.id,st.session_id,s.status session_status,e.live_monitor_enabled FROM student_live_streams st JOIN sessions s ON s.id=st.session_id JOIN exams e ON e.id=s.exam_id WHERE st.id=?").get(req.params.id);
 if(!stream||stream.session_status!=="in_progress"||!stream.live_monitor_enabled)return res.status(404).json({error:"Live stream not found or monitoring disabled."});
 const sdp=String(req.body?.answerSdp||"");if(sdp.length<20||sdp.length>200000)return res.status(400).json({error:"Invalid live stream answer."});
 db.prepare("UPDATE student_live_streams SET answer_sdp=?,status='connected',answered_at=? WHERE id=?").run(sdp,now(),stream.id);
 res.json({ok:true,status:"connected"});
});

app.get("/api/admin/live",auth,admin,(req,res)=>{
 const sessions=db.prepare("SELECT s.id,s.status,s.started_at,e.id exam_id,e.title exam_title,e.duration_minutes,e.live_monitor_enabled,u.email,u.full_name,u.batch,(SELECT COUNT(*) FROM events ev WHERE ev.session_id=s.id) event_count,(SELECT ev.event_type FROM events ev WHERE ev.session_id=s.id ORDER BY ev.occurred_at DESC LIMIT 1) latest_event,(SELECT ev.occurred_at FROM events ev WHERE ev.session_id=s.id ORDER BY ev.occurred_at DESC LIMIT 1) latest_event_at FROM sessions s JOIN users u ON u.id=s.user_id JOIN exams e ON e.id=s.exam_id WHERE s.status='in_progress' ORDER BY s.started_at DESC").all();const exams=db.prepare("SELECT e.id,e.title,e.status,e.live_monitor_enabled,e.available_from,e.available_until,(SELECT COUNT(*) FROM sessions ss WHERE ss.exam_id=e.id AND ss.status='in_progress') active_count FROM exams e WHERE e.status IN ('published','draft') ORDER BY e.created_at DESC").all();res.json({sessions,exams,liveVideoAvailable:true,notice:"Live feeds are available only for exams with monitoring enabled and after student camera consent."})
});

app.get("/api/sessions/:id/messages",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status FROM sessions WHERE id=?").get(req.params.id);
 if(!session||session.status!=="in_progress")return res.status(404).json({error:"Active session not found"});
 if(req.user.role!=="admin"&&session.user_id!==req.user.sub)return res.status(403).json({error:"Session access denied"});
 const rows=db.prepare("SELECT m.id,m.session_id,m.sender_id,m.body,m.created_at,u.role sender_role,u.email sender_email FROM chat_messages m JOIN users u ON u.id=m.sender_id WHERE m.session_id=? ORDER BY m.created_at DESC LIMIT 100").all(session.id).reverse();
 res.json({messages:rows});
});
app.post("/api/sessions/:id/messages",auth,(req,res)=>{
 const session=db.prepare("SELECT id,user_id,status FROM sessions WHERE id=?").get(req.params.id);
 if(!session||session.status!=="in_progress")return res.status(404).json({error:"Active session not found"});
 if(req.user.role!=="admin"&&session.user_id!==req.user.sub)return res.status(403).json({error:"Session access denied"});
 const body=String(req.body?.body||"").trim();
 if(!body||body.length>2000)return res.status(400).json({error:"Message must contain 1–2000 characters."});
 const id=randomUUID(),created=now();db.prepare("INSERT INTO chat_messages(id,session_id,sender_id,body,created_at) VALUES(?,?,?,?,?)").run(id,session.id,req.user.sub,body,created);
 res.status(201).json({message:{id,session_id:session.id,sender_id:req.user.sub,body,created_at:created}});
});
app.post("/api/admin/messages/broadcast",auth,admin,(req,res)=>{
 const body=String(req.body?.body||"").trim(),sessionId=String(req.body?.sessionId||"").trim(),examId=String(req.body?.examId||"").trim();
 if(!body||body.length>2000)return res.status(400).json({error:"Message must contain 1–2000 characters."});
 let sessions;
 if(sessionId){const row=db.prepare("SELECT id FROM sessions WHERE id=? AND status='in_progress'").get(sessionId);if(!row)return res.status(404).json({error:"Active session not found"});sessions=[row];}
 else if(examId){sessions=db.prepare("SELECT s.id FROM sessions s JOIN exams e ON e.id=s.exam_id WHERE s.status='in_progress' AND s.exam_id=? AND e.status='published'").all(examId);}
 else sessions=db.prepare("SELECT id FROM sessions WHERE status='in_progress'").all();
 const created=now(),insert=db.prepare("INSERT INTO chat_messages(id,session_id,sender_id,body,created_at) VALUES(?,?,?,?,?)");
 const save=db.transaction(()=>sessions.forEach(s=>insert.run(randomUUID(),s.id,req.user.sub,body,created)));
 save();res.status(201).json({ok:true,deliveredToSessions:sessions.length,createdAt:created});
});

app.delete("/api/admin/exams/:id",auth,admin,(req,res)=>{
 const e=db.prepare("SELECT id,status,title FROM exams WHERE id=?").get(req.params.id);if(!e)return res.status(404).json({error:"Exam not found"});
 const attempts=db.prepare("SELECT COUNT(*) n FROM sessions WHERE exam_id=?").get(e.id).n;
 if(attempts)return res.status(409).json({error:"This test has "+attempts+" attempt record(s). It cannot be permanently deleted because that would break the audit trail. Archive it instead."});
 db.transaction(()=>{db.prepare("DELETE FROM questions WHERE exam_id=?").run(e.id);db.prepare("DELETE FROM exams WHERE id=?").run(e.id)})();res.json({ok:true,deletedExamId:e.id,title:e.title});
});
app.post("/api/admin/exams/:id/archive",auth,admin,(req,res)=>{const e=db.prepare("SELECT id FROM exams WHERE id=?").get(req.params.id);if(!e)return res.status(404).json({error:"Exam not found"});if(e.status==="archived")return res.json({ok:true,alreadyArchived:true});db.prepare("UPDATE exams SET status='archived' WHERE id=?").run(e.id);res.json({ok:true})});
app.put("/api/admin/exams/:id",auth,admin,(req,res)=>{
 const e=db.prepare("SELECT * FROM exams WHERE id=?").get(req.params.id);if(!e)return res.status(404).json({error:"Exam not found"});
 if(e.status!=="draft")return res.status(409).json({error:"Only draft tests can be edited. Duplicate the test to create a new draft."});
 const title=String(req.body?.title??e.title).trim(),duration=Number(req.body?.durationMinutes??e.duration_minutes);
 const targetBatch=String(req.body?.targetBatch??e.target_batch??"All batches").trim().slice(0,100)||"All batches";
 const liveMonitorEnabled=(req.body?.liveMonitorEnabled===undefined?Boolean(e.live_monitor_enabled):Boolean(req.body.liveMonitorEnabled))?1:0;
 const availableFrom=String(req.body?.availableFrom??e.available_from??"").trim(),availableUntil=String(req.body?.availableUntil??e.available_until??"").trim();
 const attemptLimit=Number(req.body?.attemptLimit??e.attempt_limit??1);
 if(!title||title.length>160||!Number.isInteger(duration)||duration<1||duration>600)return res.status(400).json({error:"Enter a title and duration between 1 and 600 minutes."});
 if(!Number.isInteger(attemptLimit)||attemptLimit<0||attemptLimit>50)return res.status(400).json({error:"Attempt limit must be 0 (unlimited) or between 1 and 50."});
 if((availableFrom&& !Number.isFinite(Date.parse(availableFrom)))||(availableUntil&& !Number.isFinite(Date.parse(availableUntil))))return res.status(400).json({error:"Availability dates must be valid date/time values."});
 if(availableFrom&&availableUntil&&Date.parse(availableUntil)<=Date.parse(availableFrom))return res.status(400).json({error:"The end time must be later than the start time."});
 db.prepare("UPDATE exams SET title=?,duration_minutes=?,target_batch=?,available_from=?,available_until=?,attempt_limit=?,live_monitor_enabled=? WHERE id=?").run(title,duration,targetBatch,availableFrom,availableUntil,attemptLimit,liveMonitorEnabled,e.id);res.json({ok:true,id:e.id,title,duration_minutes:duration,target_batch:targetBatch,available_from:availableFrom,available_until:availableUntil,attempt_limit:attemptLimit,live_monitor_enabled:liveMonitorEnabled});
});
app.post("/api/admin/exams/:id/duplicate",auth,admin,(req,res)=>{
 const source=db.prepare("SELECT * FROM exams WHERE id=?").get(req.params.id);if(!source)return res.status(404).json({error:"Test not found"});
 const title=String(req.body?.title||("Copy of "+source.title)).trim().slice(0,160);if(!title)return res.status(400).json({error:"A title is required."});
 const id=randomUUID(),created=now();
 const copy=db.transaction(()=>{db.prepare("INSERT INTO exams(id,title,duration_minutes,status,created_at,target_batch,available_from,available_until,attempt_limit,live_monitor_enabled) VALUES(?,?,?,'draft',?,?,?,?,?,?)").run(id,title,source.duration_minutes,created,source.target_batch||"All batches","","",source.attempt_limit??1,source.live_monitor_enabled===0?0:1);
  const qs=db.prepare("SELECT subject,chapter,difficulty,prompt,options_json,answer_index,explanation,position FROM questions WHERE exam_id=? ORDER BY position").all(source.id);
  const insert=db.prepare("INSERT INTO questions(id,exam_id,subject,chapter,difficulty,prompt,options_json,answer_index,explanation,position,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
  qs.forEach(q=>insert.run(randomUUID(),id,q.subject,q.chapter,q.difficulty,q.prompt,q.options_json,q.answer_index,q.explanation,q.position,created));
  return qs.length;
 });
 const count=copy();res.status(201).json({exam:{id,title,duration_minutes:source.duration_minutes,status:"draft",question_count:count,target_batch:source.target_batch||"All batches",attempt_limit:source.attempt_limit??1,live_monitor_enabled:source.live_monitor_enabled===0?0:1}});
});
app.get("/api/admin/exams/:id/preview",auth,admin,(req,res)=>{const exam=db.prepare("SELECT id,title,duration_minutes,status FROM exams WHERE id=?").get(req.params.id);if(!exam)return res.status(404).json({error:"Exam not found"});const questions=db.prepare("SELECT position,subject,chapter,difficulty,prompt,options_json,answer_index,explanation FROM questions WHERE exam_id=? ORDER BY position").all(exam.id).map(q=>({...q,options:JSON.parse(q.options_json)}));res.json({exam,questions})});
app.get("/api/exams", auth, (req, res) => {
  let rows;
  if(req.user.role==="admin"){
    rows=db.prepare("SELECT e.*, (SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) question_count, (SELECT COUNT(*) FROM sessions ss WHERE ss.exam_id=e.id) attempt_count FROM exams e ORDER BY created_at DESC").all();
  }else{
    const user=db.prepare("SELECT batch FROM users WHERE id=? AND role='candidate'").get(req.user.sub);
    if(!user)return res.status(403).json({error:"Only student accounts can view tests."});
    const current=now();
    rows=db.prepare("SELECT e.id,e.title,e.duration_minutes,e.status,e.created_at,e.target_batch,e.available_from,e.available_until,e.attempt_limit,e.live_monitor_enabled,(SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) question_count,(SELECT COUNT(*) FROM sessions ss WHERE ss.exam_id=e.id AND ss.user_id=?) attempts_used FROM exams e WHERE e.status='published' AND (e.target_batch='All batches' OR e.target_batch=?) AND (e.available_until='' OR e.available_until>=?) ORDER BY CASE WHEN e.available_from<>'' AND e.available_from>? THEN 0 ELSE 1 END,e.available_from,e.created_at DESC").all(req.user.sub,user.batch||"General",current,current);
  }
  res.json({ exams: rows });
});
app.post("/api/admin/exams", auth, admin, (req, res) => {
  const title = String(req.body?.title || "").trim();
  const duration = Number(req.body?.durationMinutes || 180);
  if (!title || title.length > 160 || !Number.isInteger(duration) || duration < 1 || duration > 600) return res.status(400).json({ error: "Title and duration (1–600 minutes) are required." });
  const id = randomUUID(),created=now();db.prepare("INSERT INTO exams(id,title,duration_minutes,status,created_at,target_batch,available_from,available_until,attempt_limit,live_monitor_enabled) VALUES(?,?,?,'draft',?,?,?,?,?,1)").run(id,title,duration,created,"All batches","","",1);
  res.status(201).json({ exam: { id,title,duration_minutes:duration,status:"draft",target_batch:"All batches",available_from:"",available_until:"",attempt_limit:1 } });
});
app.post("/api/admin/exams/:id/questions",auth,admin,(req,res)=>{
 const exam=db.prepare("SELECT id,status FROM exams WHERE id=?").get(req.params.id);if(!exam)return res.status(404).json({error:"Test not found"});if(exam.status!=="draft")return res.status(409).json({error:"Only draft tests can be edited."});
 const q=req.body?.question;if(!q)return res.status(400).json({error:"Provide one question object."});
 try{validateQuestion(q,0)}catch(e){return res.status(400).json({error:e.message})}
 const count=db.prepare("SELECT COUNT(*) n FROM questions WHERE exam_id=?").get(exam.id).n;if(count>=180)return res.status(400).json({error:"This test already contains 180 questions. Remove or edit a question first."});
 const position=db.prepare("SELECT COALESCE(MAX(position),0)+1 n FROM questions WHERE exam_id=?").get(exam.id).n,id=randomUUID();
 db.prepare("INSERT INTO questions(id,exam_id,subject,chapter,difficulty,prompt,options_json,answer_index,explanation,position,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(id,exam.id,q.subject,q.chapter||"",q.difficulty||"medium",q.prompt.trim(),JSON.stringify(q.options),q.answerIndex,String(q.explanation||""),position,now());
 res.status(201).json({ok:true,questionId:id,position});
});
app.put("/api/admin/exams/:id/questions/:questionId",auth,admin,(req,res)=>{
 const exam=db.prepare("SELECT id,status FROM exams WHERE id=?").get(req.params.id);if(!exam)return res.status(404).json({error:"Test not found"});if(exam.status!=="draft")return res.status(409).json({error:"Only draft tests can be edited."});
 const existing=db.prepare("SELECT id FROM questions WHERE id=? AND exam_id=?").get(req.params.questionId,exam.id);if(!existing)return res.status(404).json({error:"Question not found."});
 const q=req.body?.question;if(!q)return res.status(400).json({error:"Provide a question object."});
 try{validateQuestion(q,0)}catch(e){return res.status(400).json({error:e.message})}
 db.prepare("UPDATE questions SET subject=?,chapter=?,difficulty=?,prompt=?,options_json=?,answer_index=?,explanation=? WHERE id=? AND exam_id=?").run(q.subject,q.chapter||"",q.difficulty||"medium",q.prompt.trim(),JSON.stringify(q.options),q.answerIndex,String(q.explanation||""),existing.id,exam.id);
 res.json({ok:true,questionId:existing.id});
});
app.delete("/api/admin/exams/:id/questions/:questionId",auth,admin,(req,res)=>{
 const exam=db.prepare("SELECT id,status FROM exams WHERE id=?").get(req.params.id);if(!exam)return res.status(404).json({error:"Test not found"});if(exam.status!=="draft")return res.status(409).json({error:"Only draft tests can be edited."});
 const question=db.prepare("SELECT id,position FROM questions WHERE id=? AND exam_id=?").get(req.params.questionId,exam.id);if(!question)return res.status(404).json({error:"Question not found."});
 db.transaction(()=>{db.prepare("DELETE FROM questions WHERE id=?").run(question.id);const rows=db.prepare("SELECT id FROM questions WHERE exam_id=? ORDER BY position").all(exam.id);const upd=db.prepare("UPDATE questions SET position=? WHERE id=?");rows.forEach((row,i)=>upd.run(i+1,row.id))})();
 res.json({ok:true,deletedQuestionId:question.id});
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
  if (exam.status!=="draft") return res.status(409).json({error:"Only draft tests can be published. Duplicate an existing test to create a new draft."});
  const qs = db.prepare("SELECT subject,COUNT(*) n FROM questions WHERE exam_id=? GROUP BY subject").all(exam.id);
  const counts = Object.fromEntries(qs.map(q=>[q.subject,q.n]));
  const total = qs.reduce((n,q)=>n+q.n,0);
  if (total !== 180 || counts.Physics !== 45 || counts.Chemistry !== 45 || counts.Biology !== 90) return res.status(400).json({ error: "NEET-style exam must contain exactly 180 questions: Physics 45, Chemistry 45, Biology 90.", counts, total });
  db.prepare("UPDATE exams SET status='published' WHERE id=?").run(exam.id);
  res.json({ ok:true, examId:exam.id, questionCount:180, counts });
});
app.get("/api/student/active-session",auth,(req,res)=>{
 if(req.user.role!=="candidate")return res.status(403).json({error:"Only student accounts have active test sessions."});
 const session=db.prepare("SELECT * FROM sessions WHERE user_id=? AND status='in_progress' ORDER BY started_at DESC LIMIT 1").get(req.user.sub);
 if(!session)return res.json({active:false});
 const exam=db.prepare("SELECT id,title,duration_minutes,target_batch,available_from,available_until,live_monitor_enabled FROM exams WHERE id=?").get(session.exam_id);
 if(!exam)return res.status(404).json({error:"The exam for this active session no longer exists."});
 const questions=db.prepare(qSelect).all(exam.id).map(publicQuestion);
 const savedAnswers=db.prepare("SELECT question_id,selected_index,marked_review FROM answers WHERE session_id=?").all(session.id).map(a=>({questionId:a.question_id,selectedIndex:a.selected_index,markedReview:Boolean(a.marked_review)}));
 const remainingSeconds=Math.max(0,Math.ceil((exam.duration_minutes*60000-(Date.now()-Date.parse(session.started_at)))/1000));
 res.json({active:true,expired:remainingSeconds<=0,remainingSeconds,session:{id:session.id,examId:session.exam_id,status:session.status,startedAt:session.started_at,durationMinutes:exam.duration_minutes},exam:{id:exam.id,title:exam.title,questionCount:questions.length,liveMonitorEnabled:Boolean(exam.live_monitor_enabled)},questions,savedAnswers,marking:{correct:4,incorrect:-1,unanswered:0}});
});
app.post("/api/exams/:id/sessions", auth, (req,res) => {
  if(req.user.role!=="candidate")return res.status(403).json({error:"Only student accounts can start a test."});
  const exam = db.prepare("SELECT * FROM exams WHERE id=? AND status='published'").get(req.params.id);
  if (!exam) return res.status(404).json({ error: "Published exam not found" });
  const student=db.prepare("SELECT batch FROM users WHERE id=? AND role='candidate'").get(req.user.sub);
  if(!student)return res.status(403).json({error:"Only student accounts can start a test."});
  if(exam.target_batch!=="All batches"&&exam.target_batch!==(student.batch||"General"))return res.status(403).json({error:"This test is assigned to batch "+exam.target_batch+" only."});
  const current=now();
  if(exam.available_from&&exam.available_from>current)return res.status(409).json({error:"This test is not available yet."});
  if(exam.available_until&&exam.available_until<current)return res.status(409).json({error:"The test availability window has closed."});
  const active = db.prepare("SELECT id,exam_id FROM sessions WHERE user_id=? AND status='in_progress' ORDER BY started_at DESC LIMIT 1").get(req.user.sub);
  if (active) return res.status(409).json({ error:active.exam_id===exam.id?"An active attempt already exists for this exam. Resume the existing attempt.":"You already have another active test. Resume or finish it before starting a different test.",sessionId:active.id });
  const attempts=db.prepare("SELECT COUNT(*) n FROM sessions WHERE user_id=? AND exam_id=?").get(req.user.sub,exam.id).n;
  if(exam.attempt_limit>0&&attempts>=exam.attempt_limit)return res.status(409).json({error:"You have used all "+exam.attempt_limit+" allowed attempt(s) for this test."});
  const id=randomUUID(), started=now();
  db.prepare("INSERT INTO sessions(id,exam_id,user_id,status,started_at) VALUES(?,?,?,'in_progress',?)").run(id,exam.id,req.user.sub,started);
  const questions=db.prepare(qSelect).all(exam.id).map(publicQuestion);
  res.status(201).json({ session:{id,examId:exam.id,status:"in_progress",startedAt:started,durationMinutes:exam.duration_minutes},exam:{id:exam.id,title:exam.title,questionCount:questions.length,liveMonitorEnabled:Boolean(exam.live_monitor_enabled)},questions,marking:{correct:4,incorrect:-1,unanswered:0} });
});
function ownedActiveSession(req,res) {
  const session=db.prepare("SELECT * FROM sessions WHERE id=?").get(req.params.id);
  if(!session) { res.status(404).json({error:"Session not found"}); return null; }
  if(req.user.role!=="admin" && session.user_id!==req.user.sub) { res.status(403).json({error:"Session access denied"}); return null; }
  if(session.status!=="in_progress") { res.status(409).json({error:"Session is no longer active"}); return null; }
  const exam=db.prepare("SELECT duration_minutes FROM exams WHERE id=?").get(session.exam_id);
  const expired=exam && Date.now()-Date.parse(session.started_at) > exam.duration_minutes*60_000;
  const isSubmit=req.method==="POST" && req.path.endsWith("/submit");
  if(expired && !isSubmit) { res.status(409).json({error:"Exam time limit reached. Submit the exam to finalize your answers."}); return null; }
  return session;
}
app.put("/api/sessions/:id/answers", auth, (req,res) => {
  const s=ownedActiveSession(req,res); if(!s)return;
  const {questionId,selectedIndex,markedReview=false}=req.body||{};
  const q=db.prepare("SELECT id FROM questions WHERE id=? AND exam_id=?").get(questionId,s.exam_id);
  if(!q || !(selectedIndex===null || (Number.isInteger(selectedIndex)&&selectedIndex>=0&&selectedIndex<=3)) || typeof markedReview!=="boolean") return res.status(400).json({error:"Invalid answer payload"});
  db.prepare("INSERT INTO answers(session_id,question_id,selected_index,marked_review,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(session_id,question_id) DO UPDATE SET selected_index=excluded.selected_index,marked_review=excluded.marked_review,updated_at=excluded.updated_at").run(s.id,q.id,selectedIndex,markedReview ? 1 : 0,now());
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
  const report={app:"ProctorGuard",version:"3.2.0",sessionId:s.id,examId:s.exam_id,candidateId:s.user_id,startedAt:s.started_at,submittedAt:submitted,durationSeconds:duration,totalQuestions:total,maxScore:total*4,score,correct,wrong,unattempted,accuracy:correct+wrong?Math.round(correct/(correct+wrong)*100):0,subjectBreakdown,answers:review,monitoringEvents:events,advisoryOnly:true};
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
app.get("/api/admin/results",auth,admin,(req,res)=>{
 const rows=db.prepare("SELECT s.id session_id,s.status,s.started_at,s.submitted_at,s.duration_seconds,s.score,s.correct_count,s.wrong_count,s.unattempted_count,s.report_json IS NOT NULL has_report,e.title exam_title,u.id student_id,u.email,u.full_name,u.batch,(SELECT ev.detail FROM events ev WHERE ev.session_id=s.id AND ev.event_type='admin_terminated' ORDER BY ev.occurred_at DESC LIMIT 1) termination_reason FROM sessions s JOIN exams e ON e.id=s.exam_id JOIN users u ON u.id=s.user_id ORDER BY s.started_at DESC LIMIT 500").all();
 res.json({results:rows});
});
app.get("/api/admin/dashboard", auth, admin, (req,res) => {
  const summary=db.prepare("SELECT COUNT(*) totalSessions, SUM(status='in_progress') activeSessions, SUM(status='submitted') submittedSessions, ROUND(AVG(CASE WHEN status='submitted' THEN score END),1) averageScore FROM sessions").get();
  const recent=db.prepare("SELECT s.id,s.status,s.started_at,s.submitted_at,s.score,s.correct_count,s.wrong_count,s.unattempted_count,u.email candidate,e.title exam FROM sessions s JOIN users u ON u.id=s.user_id JOIN exams e ON e.id=s.exam_id ORDER BY s.started_at DESC LIMIT 100").all();
  const alerts=db.prepare("SELECT ev.id,ev.event_type,ev.severity,ev.detail,ev.occurred_at,s.id session_id,u.email candidate FROM events ev JOIN sessions s ON s.id=ev.session_id JOIN users u ON u.id=s.user_id ORDER BY ev.occurred_at DESC LIMIT 100").all();
  res.json({summary,recentSessions:recent,alerts});
});
app.get("/api/admin/dashboard-storage",auth,admin,(_req,res)=>res.json({configured:ghStorageEnabled,lastBackupAt:lastGitHubBackupAt,lastError:lastGitHubBackupError,storageRepoConfigured:Boolean(GH_OWNER&&GH_REPO),encrypted:true}));
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
