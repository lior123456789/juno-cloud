// Juno Cloud — multi-tenant backend.
//  • Accounts (signup/login, JWT)            • Central Claude key (yours) powers every user
//  • Per-user integrations: Gmail (send + inbox→calendar), Slack, Notion, Google Calendar
//  • Server-side Claude tool-loop that acts using each user's own connected accounts
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
let ImapFlow = null; try { ImapFlow = require('imapflow').ImapFlow; } catch {}

try { for (const l of fs.readFileSync(__dirname + '/.env', 'utf8').split('\n')) { const m = l.match(/^([A-Z_]+)=(.*)$/); if (m) process.env[m[1]] = m[2]; } } catch {}
const CLAUDE_KEY = process.env.CLAUDE_API_KEY;                 // YOUR key — used for everyone
const JWT_SECRET = process.env.JWT_SECRET || 'dev-juno-secret-change-me';
const ENC_SECRET = crypto.createHash('sha256').update(process.env.ENC_SECRET || JWT_SECRET).digest();
const BASE = process.env.BASE_URL || 'https://juno-api.onrender.com';
const MODEL = 'claude-sonnet-4-6';
const DATA_DIR = process.env.DATA_DIR || __dirname;            // set to a Render disk for persistence
const DB_PATH = path.join(DATA_DIR, 'juno-data.json');

// ---------- encrypted-at-rest JSON store ----------
function enc(text) { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', ENC_SECRET, iv); const e = Buffer.concat([c.update(String(text), 'utf8'), c.final()]); return iv.toString('hex') + ':' + c.getAuthTag().toString('hex') + ':' + e.toString('hex'); }
function dec(blob) { try { const [i, t, e] = blob.split(':'); const d = crypto.createDecipheriv('aes-256-gcm', ENC_SECRET, Buffer.from(i, 'hex')); d.setAuthTag(Buffer.from(t, 'hex')); return Buffer.concat([d.update(Buffer.from(e, 'hex')), d.final()]).toString('utf8'); } catch { return ''; } }
let DB = { users: {} };
try { DB = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch {}
DB.users ||= {};
let saveTimer; function save() { clearTimeout(saveTimer); saveTimer = setTimeout(() => { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(DB_PATH, JSON.stringify(DB)); } catch (e) { console.error('save', e.message); } }, 200); }
const uid = () => crypto.randomBytes(8).toString('hex');
const lc = (s) => String(s || '').trim().toLowerCase();

function newUser(email, hash) {
  return { id: uid(), email: lc(email), hash, createdAt: Date.now(),
    tasks: [], events: [], messages: [], activity: [], seenMail: [],
    integrations: {} /* gmail:{user,pass(enc)}, slack:{token(enc),team}, notion:{token(enc)}, google:{refresh(enc)} */ };
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ---------- auth ----------
function sign(u) { return jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '60d' }); }

// ----- Firebase ID token verification (email/password + Google sign-in) -----
const FB_PID = process.env.FIREBASE_PROJECT_ID || '';
let CERTS = {}, CERTS_AT = 0;
async function getCerts() {
  if (Object.keys(CERTS).length && Date.now() - CERTS_AT < 3600e3) return CERTS;
  try { CERTS = await (await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')).json(); CERTS_AT = Date.now(); } catch {}
  return CERTS;
}
async function verifyFirebase(idToken) {
  if (!FB_PID || !idToken || idToken.split('.').length !== 3) return null;
  const dec = jwt.decode(idToken, { complete: true });
  if (!dec || !dec.header || !dec.header.kid) return null;
  const cert = (await getCerts())[dec.header.kid]; if (!cert) return null;
  try { return jwt.verify(idToken, cert, { algorithms: ['RS256'], audience: FB_PID, issuer: 'https://securetoken.google.com/' + FB_PID }); } catch { return null; }
}
function userFromFirebase(fb) {
  let u = Object.values(DB.users).find(x => x.fbid === fb.user_id || (fb.email && x.email === lc(fb.email)));
  if (!u) { u = newUser(fb.email || (fb.user_id + '@firebase'), ''); u.fbid = fb.user_id; DB.users[u.id] = u; save(); }
  else if (!u.fbid) { u.fbid = fb.user_id; save(); }
  return u;
}
async function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '') || req.query.token;
  try {
    const fb = await verifyFirebase(t);
    if (fb) { req.user = userFromFirebase(fb); return next(); }
    const p = jwt.verify(t, JWT_SECRET); const u = DB.users[p.uid]; if (!u) throw 0; req.user = u; next();
  } catch { res.status(401).json({ error: 'unauthorized' }); }
}
function publicUser(u) {
  const I = u.integrations || {};
  return { id: u.id, email: u.email, connections: {
    gmail: !!I.gmail, slack: !!I.slack, notion: !!I.notion, google: !!I.google,
    slackTeam: I.slack?.team || null, brain: !!CLAUDE_KEY,
  } };
}

app.get('/health', (_q, r) => r.json({ ok: true, brain: !!CLAUDE_KEY, users: Object.keys(DB.users).length }));

app.post('/api/signup', async (req, res) => {
  const email = lc(req.body.email), pw = req.body.password || '';
  if (!email || pw.length < 6) return res.status(400).json({ error: 'Email and a 6+ char password required.' });
  if (Object.values(DB.users).some(u => u.email === email)) return res.status(409).json({ error: 'That email already has an account — log in instead.' });
  const u = newUser(email, await bcrypt.hash(pw, 10)); DB.users[u.id] = u; save();
  res.json({ token: sign(u), user: publicUser(u) });
});
app.post('/api/login', async (req, res) => {
  const email = lc(req.body.email), pw = req.body.password || '';
  const u = Object.values(DB.users).find(u => u.email === email);
  if (!u || !(await bcrypt.compare(pw, u.hash))) return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(u), user: publicUser(u) });
});
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user), tasks: req.user.tasks, events: req.user.events, activity: req.user.activity.slice(0, 50) }));

// ---------- per-user helpers ----------
function logAct(u, kind, text) { u.activity.unshift({ id: uid(), kind, text, at: new Date().toISOString() }); u.activity = u.activity.slice(0, 80); save(); }

// ----- Gmail (app password) -----
function gmailTransport(u) { const g = u.integrations.gmail; if (!g) return null; return nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: g.user, pass: dec(g.pass) } }); }
async function sendEmail(u, { to, subject, body }) { const t = gmailTransport(u); if (!t) throw new Error('Gmail not connected.'); await t.sendMail({ from: `${u.email} (via Juno) <${u.integrations.gmail.user}>`, to, subject, text: body }); logAct(u, 'email', `Sent email to ${to}: “${subject}”`); return true; }

// ----- Slack -----
async function slackPost(u, { channel, text }) {
  const s = u.integrations.slack; if (!s) throw new Error('Slack not connected.');
  const r = await fetch('https://slack.com/api/chat.postMessage', { method: 'POST', headers: { authorization: 'Bearer ' + dec(s.token), 'content-type': 'application/json' }, body: JSON.stringify({ channel: channel || s.defaultChannel || '#general', text }) });
  const d = await r.json(); if (!d.ok) throw new Error('Slack: ' + d.error); logAct(u, 'slack', `Posted to Slack ${channel || ''}: “${text.slice(0, 50)}”`); return true;
}
// ----- Notion -----
async function notionAdd(u, { title, content }) {
  const n = u.integrations.notion; if (!n) throw new Error('Notion not connected.');
  const tok = dec(n.token);
  let dbId = n.dbId;
  if (!dbId) { const s = await (await fetch('https://api.notion.com/v1/search', { method: 'POST', headers: { authorization: 'Bearer ' + tok, 'Notion-Version': '2022-06-28', 'content-type': 'application/json' }, body: JSON.stringify({ filter: { property: 'object', value: 'database' } }) })).json(); dbId = s.results?.[0]?.id; if (dbId) { n.dbId = dbId; save(); } }
  if (!dbId) throw new Error('No Notion database shared with Juno yet.');
  const titleProp = 'Name';
  const r = await fetch('https://api.notion.com/v1/pages', { method: 'POST', headers: { authorization: 'Bearer ' + tok, 'Notion-Version': '2022-06-28', 'content-type': 'application/json' }, body: JSON.stringify({ parent: { database_id: dbId }, properties: { [titleProp]: { title: [{ text: { content: title } }] } }, children: content ? [{ object: 'block', type: 'paragraph', paragraph: { rich_text: [{ text: { content: content } }] } }] : [] }) });
  const d = await r.json(); if (d.object === 'error') throw new Error('Notion: ' + d.message); logAct(u, 'notion', `Added Notion page: “${title}”`); return true;
}

// ---------- Claude tool-loop (uses YOUR key, acts as the logged-in user) ----------
const TOOLS = [
  { name: 'add_event', description: "Add an event to the user's calendar.", input_schema: { type: 'object', properties: { title: { type: 'string' }, start: { type: 'string', description: 'ISO datetime' }, end: { type: 'string' }, notes: { type: 'string' } }, required: ['title', 'start'] } },
  { name: 'add_task', description: 'Create a task / reminder.', input_schema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'complete_task', description: 'Mark a task done by id or text.', input_schema: { type: 'object', properties: { idOrText: { type: 'string' } }, required: ['idOrText'] } },
  { name: 'list_today', description: "List today's events and open tasks.", input_schema: { type: 'object', properties: {} } },
  { name: 'send_email', description: "Send an email from the user's connected Gmail.", input_schema: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } }, required: ['to', 'subject', 'body'] } },
  { name: 'slack_message', description: 'Post a message to the user Slack workspace.', input_schema: { type: 'object', properties: { channel: { type: 'string' }, text: { type: 'string' } }, required: ['text'] } },
  { name: 'notion_add', description: 'Add a page/task to the user Notion.', input_schema: { type: 'object', properties: { title: { type: 'string' }, content: { type: 'string' } }, required: ['title'] } },
];
async function gcalInsert(access, ev) {
  const r = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', { method: 'POST', headers: { authorization: 'Bearer ' + access, 'content-type': 'application/json' }, body: JSON.stringify({ summary: ev.title, description: ev.notes || '', start: { dateTime: new Date(ev.start).toISOString() }, end: { dateTime: new Date(ev.end).toISOString() } }) });
  const d = await r.json(); if (d.error) throw new Error(d.error.message); return d;
}
async function runTool(u, name, input) {
  if (name === 'add_event') {
    const ev = { id: uid(), title: input.title, start: input.start, end: input.end || new Date(new Date(input.start).getTime() + 36e5).toISOString(), notes: input.notes || '' };
    let synced = false; const g = u.integrations.google;
    if (g && g.access) { try { await gcalInsert(dec(g.access), ev); synced = true; } catch {} }
    u.events.push(ev); logAct(u, 'calendar', `📅 Scheduled “${ev.title}”${synced ? ' (Google Calendar)' : ''}`); save();
    return `Added “${ev.title}” on ${new Date(ev.start).toLocaleString()}${synced ? ', synced to your Google Calendar.' : '.'}`;
  }
  if (name === 'add_task') { u.tasks.unshift({ id: uid(), text: input.text, done: false, at: new Date().toISOString() }); logAct(u, 'task', `✅ Task: ${input.text}`); save(); return `Task added: ${input.text}`; }
  if (name === 'complete_task') { const q = lc(input.idOrText); const t = u.tasks.find(t => t.id === input.idOrText || lc(t.text).includes(q)); if (t) { t.done = true; save(); return 'Done: ' + t.text; } return 'No matching task.'; }
  if (name === 'list_today') { const today = new Date().toDateString(); const evs = u.events.filter(e => new Date(e.start).toDateString() === today).map(e => `${new Date(e.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} — ${e.title}`); const ts = u.tasks.filter(t => !t.done).map(t => '• ' + t.text); return `Events today:\n${evs.join('\n') || 'none'}\n\nOpen tasks:\n${ts.join('\n') || 'none'}`; }
  if (name === 'send_email') return (await sendEmail(u, input), `Email sent to ${input.to}.`);
  if (name === 'slack_message') return (await slackPost(u, input), 'Posted to Slack.');
  if (name === 'notion_add') return (await notionAdd(u, input), `Added to Notion: ${input.title}.`);
  return 'Unknown tool.';
}
async function claude(body) { const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'x-api-key': CLAUDE_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify(body) }); const d = await r.json(); if (d.error) throw new Error(d.error.message); return d; }
const SYSTEM = (u) => { const c = publicUser(u).connections; return `You are Juno, ${u.email}'s warm, sharp personal assistant. Manage their calendar, tasks, email, Slack and Notion. Be concise — talk like a great chief of staff. When asked to do something, USE TOOLS to actually do it, then confirm in one line. If a tool needs an integration that isn't connected, tell them to connect it on the Integrations page. Connected now: ${Object.entries(c).filter(([k, v]) => v && k !== 'brain').map(([k]) => k).join(', ') || 'calendar + tasks only'}. Current date/time: ${new Date().toString()}.\n\nWrite in plain, natural sentences. Never use markdown formatting — no asterisks, no dashes or bullet points, no headers. Replies are spoken aloud, so keep them short and conversational.`; };

app.post('/api/chat', auth, async (req, res) => {
  if (!CLAUDE_KEY) return res.status(500).json({ error: 'Brain not configured.' });
  const u = req.user;
  const messages = (req.body.history || []).slice(-20).map(m => ({ role: m.role, content: m.content }));
  try {
    let guard = 0;
    while (guard++ < 6) {
      const d = await claude({ model: MODEL, max_tokens: 1600, system: SYSTEM(u), tools: TOOLS, messages });
      const toolUses = (d.content || []).filter(c => c.type === 'tool_use');
      if (toolUses.length) {
        messages.push({ role: 'assistant', content: d.content });
        const results = [];
        for (const tu of toolUses) { let out; try { out = await runTool(u, tu.name, tu.input || {}); } catch (e) { out = 'Error: ' + e.message; } results.push({ type: 'tool_result', tool_use_id: tu.id, content: out }); }
        messages.push({ role: 'user', content: results });
        continue;
      }
      const text = (d.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
      return res.json({ text: text || 'Done.', user: publicUser(u), tasks: u.tasks, events: u.events, activity: u.activity.slice(0, 50) });
    }
    res.json({ text: 'Done.', tasks: u.tasks, events: u.events });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- task/event quick endpoints ----------
app.post('/api/task', auth, (req, res) => { req.user.tasks.unshift({ id: uid(), text: req.body.text, done: false, at: new Date().toISOString() }); save(); res.json({ tasks: req.user.tasks }); });
app.post('/api/task/toggle', auth, (req, res) => { const t = req.user.tasks.find(t => t.id === req.body.id); if (t) t.done = !t.done; save(); res.json({ tasks: req.user.tasks }); });

// ---------- integrations: catalog (server-driven, not hardcoded in the app) ----------
const CATALOG = [
  { key: 'gmail',  name: 'Gmail',           desc: 'Send email and let people book you by emailing Juno.', icon: '✉️', bg: 'linear-gradient(135deg,#ea4335,#ff7a6b)', kind: 'apppassword' },
  { key: 'google', name: 'Google Calendar', desc: 'Sync events straight to your Google Calendar.',         icon: '🗓️', bg: 'linear-gradient(135deg,#1a73e8,#7eb3ff)', kind: 'google' },
  { key: 'notion', name: 'Notion',          desc: 'Turn requests into Notion pages and tasks.',             icon: '📝', bg: 'linear-gradient(135deg,#111,#555)',     kind: 'token' },
  { key: 'slack',  name: 'Slack',           desc: 'Post messages to your workspace by voice or chat.',      icon: '💬', bg: 'linear-gradient(135deg,#4a154b,#a25fa3)', kind: 'oauth' },
];
function isConfigured(key) { if (key === 'slack') return !!process.env.SLACK_CLIENT_ID; if (key === 'notion-oauth') return !!process.env.NOTION_CLIENT_ID; return true; }
app.get('/api/integrations', auth, (req, res) => {
  const I = req.user.integrations || {};
  res.json({ integrations: CATALOG.map(c => ({ ...c, configured: isConfigured(c.key), connected: !!I[c.key] })) });
});

// ---------- integrations: connect ----------
// Gmail via app password (works today, no OAuth app needed)
app.post('/api/connect/gmail', auth, async (req, res) => {
  const { user, pass } = req.body || {}; if (!user || !pass) return res.status(400).json({ error: 'Email + app password required.' });
  try { const t = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user, pass } }); await t.verify(); }
  catch (e) { return res.status(400).json({ error: 'Could not sign in — check the address and 16-char app password.' }); }
  req.user.integrations.gmail = { user, pass: enc(pass) }; save(); logAct(req.user, 'email', 'Connected Gmail inbox'); res.json({ user: publicUser(req.user) });
});
// Notion via internal integration token (paste) OR OAuth (below)
app.post('/api/connect/notion-token', auth, async (req, res) => {
  const tok = (req.body.token || '').trim(); if (!tok) return res.status(400).json({ error: 'Token required.' });
  const r = await fetch('https://api.notion.com/v1/users/me', { headers: { authorization: 'Bearer ' + tok, 'Notion-Version': '2022-06-28' } }); const d = await r.json();
  if (d.object === 'error') return res.status(400).json({ error: 'Invalid Notion token.' });
  req.user.integrations.notion = { token: enc(tok) }; save(); logAct(req.user, 'notion', 'Connected Notion'); res.json({ user: publicUser(req.user) });
});
// Google Calendar + Gmail-send via the access token from Firebase Google sign-in
app.post('/api/connect/google-token', auth, (req, res) => {
  const at = (req.body.accessToken || '').trim(); if (!at) return res.status(400).json({ error: 'No Google token.' });
  req.user.integrations.google = { access: enc(at), at: Date.now() }; save(); logAct(req.user, 'calendar', 'Connected Google Calendar'); res.json({ user: publicUser(req.user) });
});
app.post('/api/disconnect', auth, (req, res) => { delete req.user.integrations[req.body.which]; save(); res.json({ user: publicUser(req.user) }); });

// ---------- OAuth: Slack, Notion, Google (env-driven; flip on once creds are set) ----------
function stateFor(u) { return jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '15m' }); }
function userFromState(s) { try { return DB.users[jwt.verify(s, JWT_SECRET).uid]; } catch { return null; } }
const ok = (k) => !!process.env[k];

app.get('/api/oauth/:prov/start', auth, (req, res) => {
  const u = req.user, st = stateFor(u), prov = req.params.prov;
  let url;
  if (prov === 'slack') { if (!ok('SLACK_CLIENT_ID')) return res.status(503).json({ error: 'Slack not configured yet.' }); url = `https://slack.com/oauth/v2/authorize?client_id=${process.env.SLACK_CLIENT_ID}&scope=chat:write,channels:read&redirect_uri=${encodeURIComponent(BASE + '/api/oauth/slack/callback')}&state=${st}`; }
  else if (prov === 'notion') { if (!ok('NOTION_CLIENT_ID')) return res.status(503).json({ error: 'Notion not configured yet.' }); url = `https://api.notion.com/v1/oauth/authorize?client_id=${process.env.NOTION_CLIENT_ID}&response_type=code&owner=user&redirect_uri=${encodeURIComponent(BASE + '/api/oauth/notion/callback')}&state=${st}`; }
  else if (prov === 'google') { if (!ok('GOOGLE_CLIENT_ID')) return res.status(503).json({ error: 'Google not configured yet.' }); const scope = encodeURIComponent('https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/gmail.send'); url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&response_type=code&access_type=offline&prompt=consent&scope=${scope}&redirect_uri=${encodeURIComponent(BASE + '/api/oauth/google/callback')}&state=${st}`; }
  else return res.status(404).json({ error: 'unknown provider' });
  res.json({ url });
});
function done(res, msg) { res.send(`<!doctype html><meta charset=utf8><body style="background:#070a12;color:#eef2fb;font-family:-apple-system,sans-serif;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><div style="font-size:46px">✅</div><h2>${msg}</h2><p style="color:#8b97b4">You can close this tab and return to Juno.</p></div>`); }
app.get('/api/oauth/slack/callback', async (req, res) => {
  const u = userFromState(req.query.state); if (!u) return res.status(400).send('bad state');
  const r = await fetch('https://slack.com/api/oauth.v2.access', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: process.env.SLACK_CLIENT_ID, client_secret: process.env.SLACK_CLIENT_SECRET, code: req.query.code, redirect_uri: BASE + '/api/oauth/slack/callback' }) });
  const d = await r.json(); if (!d.ok) return res.send('Slack error: ' + d.error);
  u.integrations.slack = { token: enc(d.access_token), team: d.team?.name }; save(); logAct(u, 'slack', 'Connected Slack'); done(res, 'Slack connected');
});
app.get('/api/oauth/notion/callback', async (req, res) => {
  const u = userFromState(req.query.state); if (!u) return res.status(400).send('bad state');
  const basic = Buffer.from(process.env.NOTION_CLIENT_ID + ':' + process.env.NOTION_CLIENT_SECRET).toString('base64');
  const r = await fetch('https://api.notion.com/v1/oauth/token', { method: 'POST', headers: { authorization: 'Basic ' + basic, 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', code: req.query.code, redirect_uri: BASE + '/api/oauth/notion/callback' }) });
  const d = await r.json(); if (!d.access_token) return res.send('Notion error');
  u.integrations.notion = { token: enc(d.access_token) }; save(); logAct(u, 'notion', 'Connected Notion'); done(res, 'Notion connected');
});
app.get('/api/oauth/google/callback', async (req, res) => {
  const u = userFromState(req.query.state); if (!u) return res.status(400).send('bad state');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, code: req.query.code, grant_type: 'authorization_code', redirect_uri: BASE + '/api/oauth/google/callback' }) });
  const d = await r.json(); if (!d.refresh_token && !d.access_token) return res.send('Google error');
  u.integrations.google = { refresh: enc(d.refresh_token || ''), access: enc(d.access_token || '') }; save(); logAct(u, 'calendar', 'Connected Google'); done(res, 'Google connected');
});

// ---------- inbox agent: poll every connected Gmail, turn mail into events/tasks ----------
async function pollUser(u) {
  const g = u.integrations.gmail; if (!ImapFlow || !g) return;
  const client = new ImapFlow({ host: 'imap.gmail.com', port: 993, secure: true, auth: { user: g.user, pass: dec(g.pass) }, logger: false });
  try {
    await client.connect(); const lock = await client.getMailboxLock('INBOX');
    try {
      for await (const msg of client.fetch({ since: new Date(Date.now() - 3 * 864e5) }, { envelope: true, source: true })) {
        const mid = msg.envelope.messageId || String(msg.uid); if (u.seenMail.includes(mid)) continue;
        u.seenMail.push(mid); u.seenMail = u.seenMail.slice(-500); save();
        const from = msg.envelope.from?.[0]?.address || 'someone'; const subject = msg.envelope.subject || '(no subject)';
        const text = msg.source.toString().slice(0, 5000);
        const d = await claude({ model: MODEL, max_tokens: 500, system: `You are Juno's inbox agent for ${u.email}. Decide if this email implies a calendar event or task. Reply ONLY JSON {"event":{"title","start":"ISO","end":"ISO","notes"}|null,"task":"text"|null,"summary":"one line"}. Today: ${new Date().toString()}.`, messages: [{ role: 'user', content: `From:${from}\nSubject:${subject}\n\n${text}` }] });
        let plan = {}; try { plan = JSON.parse(((d.content[0] || {}).text || '{}').replace(/^```(?:json)?/i, '').replace(/```$/, '').trim()); } catch {}
        if (plan.event?.title) { u.events.push({ id: uid(), ...plan.event, source: `email from ${from}` }); logAct(u, 'calendar', `📅 ${from} scheduled “${plan.event.title}” via email`); }
        if (plan.task) { u.tasks.unshift({ id: uid(), text: plan.task, done: false, source: `email from ${from}`, at: new Date().toISOString() }); logAct(u, 'task', `✅ From ${from}: ${plan.task}`); }
        save();
      }
    } finally { lock.release(); }
  } catch {} finally { try { await client.logout(); } catch {} }
}
let polling = false;
async function pollAll() { if (polling) return; polling = true; for (const u of Object.values(DB.users)) { try { await pollUser(u); } catch {} } polling = false; }
setInterval(pollAll, 90000); setTimeout(pollAll, 8000);

const PORT = process.env.PORT || 4500;
app.listen(PORT, () => console.log(`🌙 Juno Cloud on :${PORT} — brain:${!!CLAUDE_KEY} users:${Object.keys(DB.users).length}`));
