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
    tasks: [], events: [], messages: [], activity: [], seenMail: [], memories: [], agents: [],
    integrations: {} /* gmail:{user,pass(enc)}, slack:{token(enc),team}, notion:{token(enc)}, google:{refresh(enc)} */ };
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '14mb' })); // room for uploaded PDFs/images

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
// One-step: log in if the account exists, otherwise create it. (Powers the single "Continue" button.)
app.post('/api/auth', async (req, res) => {
  const email = lc(req.body.email), pw = req.body.password || '';
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  let u = Object.values(DB.users).find(u => u.email === email);
  if (u) {
    if (!u.hash || !(await bcrypt.compare(pw, u.hash))) return res.status(401).json({ error: 'Wrong password for that account.' });
  } else {
    u = newUser(email, await bcrypt.hash(pw, 10)); DB.users[u.id] = u; save();
  }
  res.json({ token: sign(u), user: publicUser(u), created: !u.lastLogin });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user), tasks: req.user.tasks, events: req.user.events, activity: req.user.activity.slice(0, 50), memories: req.user.memories || [] }));
app.post('/api/memory/delete', auth, (req, res) => { req.user.memories = (req.user.memories || []).filter(m => m.id !== req.body.id); save(); res.json({ memories: req.user.memories }); });
app.post('/api/memory/add', auth, (req, res) => { const f = (req.body.fact || '').trim(); if (f) { req.user.memories = req.user.memories || []; req.user.memories.unshift({ id: uid(), text: f, at: new Date().toISOString() }); save(); } res.json({ memories: req.user.memories }); });

// ---------- per-user helpers ----------
function logAct(u, kind, text) { u.activity.unshift({ id: uid(), kind, text, at: new Date().toISOString() }); u.activity = u.activity.slice(0, 80); save(); }

// ----- Gmail (app password) -----
function gmailTransport(u) { const g = u.integrations.gmail; if (!g) return null; return nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: g.user, pass: dec(g.pass) } }); }
async function sendEmail(u, { to, subject, body }) { const t = gmailTransport(u); if (!t) throw new Error('Gmail not connected.'); await t.sendMail({ from: `${u.email} (via Juno) <${u.integrations.gmail.user}>`, to, subject, text: body }); logAct(u, 'email', `Sent email to ${to}: “${subject}”`); return true; }

// Zero-setup Google Calendar: email an iCalendar invite to the user's own Gmail.
// Google auto-adds invites where the recipient is an accepted attendee — so it lands on their calendar.
function icsFor(u, ev) {
  const flo = (s) => String(s).replace(/[-:]/g, '').slice(0, 15);              // floating local wall-clock (no TZ shift)
  const utc = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const email = u.integrations.gmail.user;
  const esc = (x) => String(x || '').replace(/([,;\\])/g, '\\$1').replace(/\n/g, '\\n');
  return ['BEGIN:VCALENDAR', 'PRODID:-//Juno//EN', 'VERSION:2.0', 'CALSCALE:GREGORIAN', 'METHOD:REQUEST',
    'BEGIN:VEVENT', `UID:${ev.id}@juno`, `DTSTAMP:${utc()}`, `DTSTART:${flo(ev.start)}`, `DTEND:${flo(ev.end)}`,
    `SUMMARY:${esc(ev.title || 'Event')}`, `DESCRIPTION:${esc(ev.notes || 'Scheduled by Juno')}`,
    `ORGANIZER;CN=${email}:mailto:${email}`,
    `ATTENDEE;CN=${email};PARTSTAT=ACCEPTED;RSVP=FALSE:mailto:${email}`,
    'STATUS:CONFIRMED', 'SEQUENCE:0', 'END:VEVENT', 'END:VCALENDAR'].join('\r\n');
}
async function sendCalInvite(u, ev) {
  const t = gmailTransport(u); if (!t) return false;
  const email = u.integrations.gmail.user;
  await t.sendMail({
    from: email, to: email,
    subject: `Invitation: ${ev.title} @ ${new Date(ev.start).toDateString()}`,
    text: `${ev.title}\n${ev.start}`,
    icalEvent: { method: 'REQUEST', filename: 'invite.ics', content: icsFor(u, ev) },
  });
  return true;
}

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

// On-demand: read recent Gmail, turn meeting invites into events and work items into tasks (deduped).
async function scanInboxNow(u, limit = 15) {
  const g = u.integrations.gmail; if (!ImapFlow || !g) return [];
  const client = new ImapFlow({ host: 'imap.gmail.com', port: 993, secure: true, auth: { user: g.user, pass: dec(g.pass) }, logger: false });
  const out = [];
  try {
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    try {
      const all = [];
      for await (const msg of client.fetch({ since: new Date(Date.now() - 6 * 864e5) }, { envelope: true, source: true })) all.push(msg);
      for (const msg of all.slice(-limit)) {
        const from = (msg.envelope.from && msg.envelope.from[0] && msg.envelope.from[0].address) || 'someone';
        const subject = msg.envelope.subject || '(no subject)';
        const text = msg.source.toString().slice(0, 5000);
        const sys = `You are Juno's inbox planner for ${u.email}. Classify this email and plan for it. Reply ONLY JSON: {"type":"meeting"|"task"|"fyi","event":{"title":"","start":"ISO datetime","end":"ISO datetime","notes":""}|null,"task":"short action text"|null,"summary":"one short line describing what you did, or why it is just FYI"}. Treat calendar invites, calls, and scheduled work as meetings (make an event). Treat requests, deadlines, and to-dos as tasks. Today is ${new Date().toString()}.`;
        let plan = {};
        try { const d = await claude({ model: MODEL, max_tokens: 500, system: sys, messages: [{ role: 'user', content: `From: ${from}\nSubject: ${subject}\n\n${text}` }] }); plan = JSON.parse(((d.content[0] || {}).text || '{}').replace(/^```(?:json)?/i, '').replace(/```$/, '').trim()); } catch { continue; }
        if (plan.event && plan.event.title) {
          const dup = u.events.some(e => e.title === plan.event.title && new Date(e.start).getTime() === new Date(plan.event.start).getTime());
          if (!dup) { u.events.push({ id: uid(), title: plan.event.title, start: plan.event.start, end: plan.event.end || new Date(new Date(plan.event.start).getTime() + 36e5).toISOString(), notes: plan.event.notes || '', source: `email from ${from}` }); logAct(u, 'calendar', `📅 Planned “${plan.event.title}” from ${from}`); }
        }
        if (plan.task) {
          const dup = u.tasks.some(t => t.text.toLowerCase() === String(plan.task).toLowerCase());
          if (!dup) { u.tasks.unshift({ id: uid(), text: plan.task, done: false, source: `email from ${from}`, at: new Date().toISOString() }); logAct(u, 'task', `✅ ${plan.task} (from ${from})`); }
        }
        if (plan.summary) out.push(plan.summary);
      }
      save();
    } finally { lock.release(); }
  } catch (e) { /* return whatever we got */ } finally { try { await client.logout(); } catch {} }
  return out;
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
  { name: 'remember', description: "Save a durable fact about the user (a preference, detail, goal, or ongoing context) so you can recall it in future chats. Use whenever the user shares something worth remembering.", input_schema: { type: 'object', properties: { fact: { type: 'string' } }, required: ['fact'] } },
  { name: 'make_pdf', description: "Generate a downloadable PDF document for the user — a resume, cover letter, report, letter, invoice, study sheet, etc. Use this whenever the user asks to make/create/generate a PDF or a formatted document. Provide clean, well-structured HTML for the document body with inline CSS styling (headings, sections, spacing). Do NOT include <html>/<head>/<body> tags — just the inner content.", input_schema: { type: 'object', properties: { filename: { type: 'string', description: 'e.g. Lior_Resume.pdf' }, html: { type: 'string', description: 'the document body as styled HTML' } }, required: ['filename', 'html'] } },
  { name: 'scan_inbox', description: "Read the user's recent Gmail and plan for them — turn meeting invites into calendar events and work/action items into tasks. Use whenever the user asks to check their email, go through their inbox, or plan their day/week from email.", input_schema: { type: 'object', properties: {} } },
  { name: 'read_url', description: "Fetch a web page, article, or blog post by its URL and read the contents so you can summarize it, extract info, or answer questions about it.", input_schema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
];
const WEB_SEARCH = { type: 'web_search_20250305', name: 'web_search', max_uses: 5 };
// Device tools execute on the user's Mac (in the desktop app), not on the server.
const DEVICE_TOOLS = [
  { name: 'open_app', description: "Open/launch a Mac application by name (Safari, Spotify, Notes, Music, Mail, etc.).", input_schema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } },
  { name: 'run_applescript', description: "Run AppleScript on the user's Mac to control apps and the system — play/pause music, set volume, create Notes/Reminders, open URLs in Safari, toggle dark mode, etc. Give a complete, correct script.", input_schema: { type: 'object', properties: { script: { type: 'string' } }, required: ['script'] } },
  { name: 'run_shell', description: "Run a zsh shell command on the user's Mac — manage files/folders, clean the Downloads folder, git, etc. Avoid destructive commands unless the user clearly asked.", input_schema: { type: 'object', properties: { cmd: { type: 'string' } }, required: ['cmd'] } },
  { name: 'take_screenshot', description: "Capture the user's screen so you can SEE what's on it and answer questions about it.", input_schema: { type: 'object', properties: {} } },
  { name: 'read_clipboard', description: "Read the text currently on the user's clipboard.", input_schema: { type: 'object', properties: {} } },
  { name: 'write_clipboard', description: "Put text on the user's clipboard.", input_schema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'write_file', description: "Create or overwrite a file on the user's Mac with exact contents (creates parent folders automatically). Use this — NOT shell echo — to build apps and websites: call it once per file (index.html, style.css, app.js, package.json, etc.).", input_schema: { type: 'object', properties: { path: { type: 'string', description: 'absolute path, e.g. /Users/.../Desktop/myapp/index.html' }, content: { type: 'string' } }, required: ['path', 'content'] } },
  { name: 'open_path', description: "Open a file, folder, or URL on the user's Mac (e.g. open the index.html you just built in the browser, or reveal the project folder).", input_schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
];
const CLIENT_TOOLS = new Set(DEVICE_TOOLS.map(t => t.name));
const MODE_PREFIX = '\n\nIMPORTANT — fully commit to this mode; it must noticeably change your tone, style and structure compared to your default voice:';
const MODES = {
  professional: MODE_PREFIX + ' Professional mode. Crisp, direct, businesslike. Plain factual language — NO poetic or flowery wording, no metaphors, no filler. Lead with the point. Sound like a polished business memo.',
  friendly: MODE_PREFIX + ' Friendly mode. Warm, casual, upbeat, a little playful. Use everyday language and the occasional emoji. Sound like a supportive friend.',
  coach: MODE_PREFIX + ' Coach mode. Motivating and energetic. Push the user, ask one sharp question when useful, and give concrete next steps and accountability.',
  teacher: MODE_PREFIX + ' Teacher mode. Patient and structured. Explain step by step with simple examples and analogies, and check understanding.',
  programmer: MODE_PREFIX + ' Programmer mode. Act as a senior engineer. Give precise, correct, runnable code with brief explanations, edge cases, and best practices.',
  creative: MODE_PREFIX + ' Creative mode. Be a bold, expressive writer — vivid imagery, metaphor, rhythm and flair. This is art, not a report. Take imaginative risks.',
  concise: MODE_PREFIX + ' Concise mode. Answer in as few words as possible — ideally one short sentence, no preamble.',
  research: MODE_PREFIX + ' Deep research mode. Be thorough; use web_search across multiple angles. Structure findings with clear sections and note sources.',
  stepbystep: MODE_PREFIX + ' Step-by-step mode. Work through the problem methodically, numbering each step and showing the reasoning before the final answer.',
  quick: MODE_PREFIX + ' Quick mode. Give only the single best answer in one short sentence, no preamble, no explanation.',
  debate: MODE_PREFIX + ' Debate mode. Argue both sides with the strongest points for each (label them), then give a balanced verdict.',
  factcheck: MODE_PREFIX + ' Fact-check mode. Use web_search to verify, then rate True / False / Unclear and cite what you found.',
  eli5: MODE_PREFIX + " Explain-like-I'm-5 mode. Use very simple words and fun everyday analogies a child would get.",
  doctor: MODE_PREFIX + ' Doctor mode. Act as a knowledgeable medical information guide — clear and careful — and remind them you are not a substitute for a real doctor.',
  lawyer: MODE_PREFIX + ' Lawyer mode. Act as a legal information guide — explain clearly in plain terms — and note this is general information, not legal advice.',
  engineer: MODE_PREFIX + ' Engineer mode. Act as a senior software/systems engineer giving expert, precise, practical guidance.',
};
// Get a fresh Google access token (refreshes via the stored refresh_token so sync keeps working).
async function getGoogleAccess(u) {
  const g = u.integrations.google; if (!g) return null;
  const rt = g.refresh ? dec(g.refresh) : '';
  if (rt && process.env.GOOGLE_CLIENT_ID) {
    try {
      const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, refresh_token: rt, grant_type: 'refresh_token' }) });
      const d = await r.json(); if (d.access_token) { g.access = enc(d.access_token); save(); return d.access_token; }
    } catch {}
  }
  return g.access ? dec(g.access) : null;
}
async function gcalInsert(access, ev) {
  const r = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', { method: 'POST', headers: { authorization: 'Bearer ' + access, 'content-type': 'application/json' }, body: JSON.stringify({ summary: ev.title, description: ev.notes || '', start: { dateTime: new Date(ev.start).toISOString() }, end: { dateTime: new Date(ev.end).toISOString() } }) });
  const d = await r.json(); if (d.error) throw new Error(d.error.message); return d;
}
async function runTool(u, name, input) {
  if (name === 'add_event') {
    const ev = { id: uid(), title: input.title, start: input.start, end: input.end || new Date(new Date(input.start).getTime() + 36e5).toISOString(), notes: input.notes || '' };
    let synced = false, how = '';
    try { const at = await getGoogleAccess(u); if (at) { await gcalInsert(at, ev); synced = true; how = 'google'; } } catch {}
    if (!synced && u.integrations.gmail) { try { await sendCalInvite(u, ev); synced = true; how = 'invite'; } catch {} }
    u.events.push(ev); logAct(u, 'calendar', `📅 Scheduled “${ev.title}”${synced ? ' → Google Calendar' : ''}`); save();
    const tail = how === 'google' ? ', synced to your Google Calendar.' : how === 'invite' ? ' — I sent it to your Google Calendar, it will show up there.' : '. (Connect Gmail or Google to sync it to your real calendar.)';
    return `Added “${ev.title}”${tail}`;
  }
  if (name === 'add_task') { u.tasks.unshift({ id: uid(), text: input.text, done: false, at: new Date().toISOString() }); logAct(u, 'task', `✅ Task: ${input.text}`); save(); return `Task added: ${input.text}`; }
  if (name === 'complete_task') { const q = lc(input.idOrText); const t = u.tasks.find(t => t.id === input.idOrText || lc(t.text).includes(q)); if (t) { t.done = true; save(); return 'Done: ' + t.text; } return 'No matching task.'; }
  if (name === 'list_today') { const today = new Date().toDateString(); const evs = u.events.filter(e => new Date(e.start).toDateString() === today).map(e => `${new Date(e.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} — ${e.title}`); const ts = u.tasks.filter(t => !t.done).map(t => '• ' + t.text); return `Events today:\n${evs.join('\n') || 'none'}\n\nOpen tasks:\n${ts.join('\n') || 'none'}`; }
  if (name === 'send_email') return (await sendEmail(u, input), `Email sent to ${input.to}.`);
  if (name === 'slack_message') return (await slackPost(u, input), 'Posted to Slack.');
  if (name === 'notion_add') return (await notionAdd(u, input), `Added to Notion: ${input.title}.`);
  if (name === 'scan_inbox') {
    if (!u.integrations.gmail) return 'Gmail is not connected yet — connect it on the Integrations page and I will read your inbox and plan from it.';
    const out = await scanInboxNow(u, 15);
    if (!out.length) return 'I checked your inbox and there was nothing new to plan around.';
    return `I went through your recent email and planned for it:\n${out.map(o => '- ' + o).join('\n')}`;
  }
  if (name === 'read_url') {
    try { let url = String(input.url || ''); if (!/^https?:\/\//.test(url)) url = 'https://' + url;
      const r = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (Macintosh) Juno/1.0' }, signal: AbortSignal.timeout(15000) });
      let t = await r.text();
      t = t.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/\s+/g, ' ').trim();
      return t.slice(0, 9000) || '(no readable text found on that page)';
    } catch (e) { return 'Could not read that URL: ' + e.message; }
  }
  if (name === 'remember') { const f = (input.fact || '').trim(); if (f) { u.memories = u.memories || []; if (!u.memories.some(m => m.text.toLowerCase() === f.toLowerCase())) { u.memories.unshift({ id: uid(), text: f, at: new Date().toISOString() }); u.memories = u.memories.slice(0, 120); logAct(u, 'memory', `🧠 Remembered: ${f}`); save(); } } return 'Saved — I will remember that.'; }
  return 'Unknown tool.';
}
async function claude(body) { const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'x-api-key': CLAUDE_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify(body) }); const d = await r.json(); if (d.error) throw new Error(d.error.message); return d; }
const SYSTEM = (u, mode, device) => { const c = publicUser(u).connections;
  const mems = (u.memories || []).slice(0, 50).map(m => '- ' + m.text).join('\n');
  const memBlock = mems ? `\n\nWhat you know about ${u.email} (use naturally when relevant, do not recite as a list):\n${mems}` : '';
  const modeBlock = MODES[mode] || '';
  const deviceBlock = device ? "\n\nYou are running in the desktop app and CAN control this Mac: open_app, run_applescript (Music/Notes/Reminders/Safari/volume/dark mode), run_shell (files, git, run code, start dev servers), take_screenshot, read_clipboard, write_clipboard, write_file (create files), open_path (open files/folders/URLs). When the user asks you to do something on their computer, USE these tools.\n\nBUILDING APPS & WEBSITES: when asked to build a website or app, FIRST reply with one short sentence saying what you'll build and listing the files you'll create (e.g. 'Building a coffee-shop site — index.html, style.css, script.js'). THEN create each file with write_file (use a folder like ~/Desktop/<projectname>/, write complete real code, never placeholders), run any needed shell commands (npm install, etc.) with run_shell, and finally open_path the main file or folder so the user sees it. Build complete, working projects." : '';
  return `You are Juno, ${u.email}'s warm, sharp personal assistant and a capable general AI. Besides managing their calendar, tasks, email, Slack and Notion, you also: search the web for current info, read any specific web page or link the user gives you (ALWAYS use the read_url tool when the user pastes or names a URL — never say you cannot browse), generate downloadable PDF documents (make_pdf), summarize and analyze uploaded files and images, write and rewrite text, translate, do math, write and debug code, brainstorm, and teach. Use web_search for anything time-sensitive or that you are unsure about. Be concise — talk like a great chief of staff. When asked to do something, USE TOOLS to actually do it, then confirm in one line. ACT FIRST — never interrogate. For scheduling and tasks, make sensible assumptions (a reasonable title like "Lunch", a 1-hour default duration, a sensible time of day) and call the tool IMMEDIATELY. Do NOT ask follow-up questions like "what's the title?" or "how long?" for routine requests — just do it and confirm; the user can correct you after. Only ask a question if the request is genuinely impossible to act on. If a tool needs an integration that isn't connected, tell them to connect it on the Integrations page. Connected now: ${Object.entries(c).filter(([k, v]) => v && k !== 'brain').map(([k]) => k).join(', ') || 'calendar + tasks only'}. Current date/time: ${new Date().toString()}.\n\nWrite in plain, natural sentences. Avoid heavy markdown — no decorative asterisks or bullet characters. Keep replies conversational.${deviceBlock}${modeBlock}${memBlock}`; };

// Reusable agentic loop — runs Claude with all tools until it produces a final answer. Used by chat AND by autonomous agents.
async function runJuno(u, messages, mode, device) {
  const tools = device ? [...TOOLS, ...DEVICE_TOOLS, WEB_SEARCH] : [...TOOLS, WEB_SEARCH];
  let pendingDoc = null, guard = 0;
  while (guard++ < 10) {
    const d = await claude({ model: MODEL, max_tokens: 4000, system: SYSTEM(u, mode, device), tools, messages });
    const toolUses = (d.content || []).filter(c => c.type === 'tool_use');
    if (toolUses.length) {
      messages.push({ role: 'assistant', content: d.content });
      const results = []; const clientActions = [];
      for (const tu of toolUses) {
        if (tu.name === 'make_pdf') { pendingDoc = { filename: (tu.input.filename || 'document.pdf'), html: tu.input.html || '' }; results.push({ type: 'tool_result', tool_use_id: tu.id, content: 'PDF generated and shown to the user with a Download button.' }); continue; }
        if (CLIENT_TOOLS.has(tu.name)) { clientActions.push({ id: tu.id, name: tu.name, input: tu.input || {} }); continue; }
        let out; try { out = await runTool(u, tu.name, tu.input || {}); } catch (e) { out = 'Error: ' + e.message; }
        results.push({ type: 'tool_result', tool_use_id: tu.id, content: out });
      }
      if (clientActions.length) { const preText = (d.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim(); return { clientActions, serverResults: results, messages, document: pendingDoc, text: preText }; } // hand Mac actions to the desktop app (with any "here's the plan" text)
      messages.push({ role: 'user', content: results });
      continue;
    }
    if (d.stop_reason === 'pause_turn') { messages.push({ role: 'assistant', content: d.content }); continue; }
    const text = (d.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
    return { text: text || 'Done.', document: pendingDoc };
  }
  return { text: 'Done.', document: pendingDoc };
}
function chatResult(u, out) {
  if (out.clientActions) return { clientActions: out.clientActions, serverResults: out.serverResults, messages: out.messages, document: out.document };
  return { text: out.text, document: out.document, user: publicUser(u), tasks: u.tasks, events: u.events, activity: u.activity.slice(0, 50), memories: u.memories || [] };
}
// Resume a conversation after the desktop app executed Mac actions and returned their results.
app.post('/api/chat/resume', auth, async (req, res) => {
  if (!CLAUDE_KEY) return res.status(500).json({ error: 'Brain not configured.' });
  const u = req.user; const messages = req.body.messages || []; const results = req.body.results || [];
  messages.push({ role: 'user', content: results });
  try { res.json(chatResult(u, await runJuno(u, messages, req.body.mode || '', true))); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- autonomous agents (run on a schedule, 24/7, server-side) ----------
const AGENT_FREQ = { q15: 15 * 60e3, hourly: 60 * 60e3, q6h: 6 * 3600e3, daily: 24 * 3600e3 };
const FREQ_LABEL = { q15: 'every 15 min', hourly: 'every hour', q6h: 'every 6 hours', daily: 'once a day' };
async function runAgent(u, agent) {
  agent.lastRun = Date.now();
  const messages = [{ role: 'user', content: `${agent.instruction}\n\n(You are "${agent.name}", an autonomous agent running on a schedule for ${u.email}. Take real action now using your tools — schedule events, add tasks, scan email, search the web, send messages as appropriate. Then reply with one concise line summarizing what you did this run.)` }];
  try { const { text } = await runJuno(u, messages, 'concise'); agent.lastResult = text; agent.lastResultAt = new Date().toISOString(); logAct(u, 'agent', `🤖 ${agent.name}: ${text.slice(0, 100)}`); }
  catch (e) { agent.lastResult = 'Error: ' + e.message; }
  save();
}
function agentDue(a) {
  if (!a.enabled) return false;
  const last = a.lastRun || 0;
  if (a.freq === 'daily') { const targetH = (a.hour != null ? a.hour : 8); if (new Date().getHours() !== targetH) return false; return (Date.now() - last) > 20 * 3600e3; }
  return (Date.now() - last) >= (AGENT_FREQ[a.freq] || 3600e3);
}
let agentsRunning = false;
async function tickAgents() {
  if (agentsRunning || !CLAUDE_KEY) return; agentsRunning = true;
  for (const u of Object.values(DB.users)) { for (const a of (u.agents || [])) { try { if (agentDue(a)) await runAgent(u, a); } catch {} } }
  agentsRunning = false;
}
setInterval(tickAgents, 60000); setTimeout(tickAgents, 15000);

app.get('/api/agents', auth, (req, res) => res.json({ agents: req.user.agents || [], freqLabels: FREQ_LABEL }));
app.post('/api/agents/create', auth, (req, res) => { const { name, instruction, freq, hour } = req.body || {}; if (!instruction) return res.status(400).json({ error: 'Tell the agent what to do.' }); req.user.agents = req.user.agents || []; req.user.agents.unshift({ id: uid(), name: name || 'Agent', instruction, freq: AGENT_FREQ[freq] ? freq : 'daily', hour: (hour != null ? Number(hour) : 8), enabled: true, lastRun: 0, lastResult: '', createdAt: Date.now() }); save(); res.json({ agents: req.user.agents }); });
app.post('/api/agents/toggle', auth, (req, res) => { const a = (req.user.agents || []).find(a => a.id === req.body.id); if (a) a.enabled = !a.enabled; save(); res.json({ agents: req.user.agents }); });
app.post('/api/agents/delete', auth, (req, res) => { req.user.agents = (req.user.agents || []).filter(a => a.id !== req.body.id); save(); res.json({ agents: req.user.agents }); });
app.post('/api/agents/run', auth, async (req, res) => { const a = (req.user.agents || []).find(a => a.id === req.body.id); if (!a) return res.status(404).json({ error: 'not found' }); await runAgent(req.user, a); res.json({ agents: req.user.agents, events: req.user.events, tasks: req.user.tasks, activity: req.user.activity.slice(0, 50) }); });

app.post('/api/chat', auth, async (req, res) => {
  if (!CLAUDE_KEY) return res.status(500).json({ error: 'Brain not configured.' });
  const u = req.user;
  const mode = req.body.mode || '';
  const messages = (req.body.history || []).slice(-20).map(m => ({ role: m.role, content: m.content }));
  // attach an uploaded file/image to the latest user message (PDF + image analysis)
  const a = req.body.attachment;
  if (a && a.data && messages.length) {
    const last = messages[messages.length - 1];
    const promptText = typeof last.content === 'string' ? last.content : 'Please analyze the attached file.';
    const blocks = [];
    if (a.kind === 'pdf') blocks.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: a.data } });
    else blocks.push({ type: 'image', source: { type: 'base64', media_type: a.mediaType || 'image/jpeg', data: a.data } });
    blocks.push({ type: 'text', text: promptText });
    last.content = blocks;
  }
  try {
    res.json(chatResult(u, await runJuno(u, messages, mode, !!req.body.device)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- task/event quick endpoints ----------
app.post('/api/task', auth, (req, res) => { req.user.tasks.unshift({ id: uid(), text: req.body.text, done: false, at: new Date().toISOString() }); save(); res.json({ tasks: req.user.tasks }); });
app.post('/api/task/toggle', auth, (req, res) => { const t = req.user.tasks.find(t => t.id === req.body.id); if (t) t.done = !t.done; save(); res.json({ tasks: req.user.tasks }); });
app.post('/api/event/delete', auth, (req, res) => { const before = req.user.events.length; req.user.events = req.user.events.filter(e => e.id !== req.body.id); if (req.user.events.length < before) logAct(req.user, 'calendar', '🗑️ Removed an event'); save(); res.json({ events: req.user.events }); });

// ---------- integrations: catalog (server-driven, not hardcoded in the app) ----------
const CATALOG = [
  { key: 'gmail',  name: 'Gmail',           desc: 'Send email and let people book you by emailing Juno.', icon: '✉️', bg: 'linear-gradient(135deg,#ea4335,#ff7a6b)', kind: 'apppassword' },
  { key: 'google', name: 'Google Calendar', desc: 'Sync events straight to your Google Calendar.',         icon: '🗓️', bg: 'linear-gradient(135deg,#1a73e8,#7eb3ff)', kind: 'oauth' },
  { key: 'notion', name: 'Notion',          desc: 'Turn requests into Notion pages and tasks.',             icon: '📝', bg: 'linear-gradient(135deg,#111,#555)',     kind: 'token' },
  { key: 'slack',  name: 'Slack',           desc: 'Post messages to your workspace by voice or chat.',      icon: '💬', bg: 'linear-gradient(135deg,#4a154b,#a25fa3)', kind: 'oauth' },
];
function isConfigured(key) { if (key === 'slack') return !!process.env.SLACK_CLIENT_ID; if (key === 'google') return !!process.env.GOOGLE_CLIENT_ID; return true; }
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

// never let a stray error take the whole server down (keeps the API up = no "failed to fetch")
process.on('uncaughtException', (e) => console.error('uncaughtException:', e && e.message));
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e && (e.message || e)));

const PORT = process.env.PORT || 4500;
app.listen(PORT, () => console.log(`🌙 Juno Cloud on :${PORT} — brain:${!!CLAUDE_KEY} users:${Object.keys(DB.users).length}`));
