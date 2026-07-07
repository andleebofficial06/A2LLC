/**
 * A2LLC Tutors — server
 * Pure Node.js (http + crypto + node:sqlite). No npm dependencies required,
 * so `node server.js` works with nothing but a Node 20+ runtime.
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { run, get, all } = require('./db');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'a2llc-dev-secret-change-in-production';
const PUBLIC_DIR = path.join(__dirname, 'public');

// ============================================================
// password hashing (scrypt, salted) — no bcrypt dependency needed
// ============================================================
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ============================================================
// minimal JWT-style signed token (HMAC-SHA256) — no jsonwebtoken dep
// ============================================================
function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}
function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = Object.assign({}, payload, { iat: Date.now(), exp: Date.now() + 30 * 24 * 3600 * 1000 });
  const headerPart = b64url(JSON.stringify(header));
  const bodyPart = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(headerPart + '.' + bodyPart).digest('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${headerPart}.${bodyPart}.${sig}`;
}
function verifyToken(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [headerPart, bodyPart, sig] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(headerPart + '.' + bodyPart).digest('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('Bad signature');
  const payload = JSON.parse(b64urlDecode(bodyPart));
  if (payload.exp && Date.now() > payload.exp) throw new Error('Token expired');
  return payload;
}

// ============================================================
// tiny router
// ============================================================
const routes = []; // {method, pattern, fn}
function addRoute(method, pattern, fn) {
  const paramNames = [];
  const regex = new RegExp('^' + pattern.replace(/:[^/]+/g, (m) => {
    paramNames.push(m.slice(1));
    return '([^/]+)';
  }) + '$');
  routes.push({ method, regex, paramNames, fn });
}
function get_(p, fn) { addRoute('GET', p, fn); }
function post_(p, fn) { addRoute('POST', p, fn); }

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function authUser(req) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  try { return verifyToken(token); } catch (e) { return null; }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    req.on('data', (c) => {
      chunks.push(c);
      if (chunks.reduce((n, c) => n + c.length, 0) > 1e6) req.destroy();
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ---------- helpers ----------
function makeStudentCode() {
  return 'ST' + Math.floor(10000 + Math.random() * 89999);
}
function publicUser(u) {
  if (!u) return null;
  const { password_hash, ...rest } = u;
  return rest;
}

// ============================================================
// AUTH
// ============================================================
post_('/api/auth/signup', async (req, res, params, body) => {
  const { role, name, email, password, subject, pseudonym } = body || {};
  if (!role || !['teacher', 'student'].includes(role)) return send(res, 400, { error: 'Role must be teacher or student' });
  if (!name || !email || !password) return send(res, 400, { error: 'Name, email and password are required' });
  if (password.length < 6) return send(res, 400, { error: 'Password must be at least 6 characters' });

  const cleanEmail = email.toLowerCase().trim();
  const existing = get('SELECT id FROM users WHERE email = ?', [cleanEmail]);
  if (existing) return send(res, 409, { error: 'An account with that email already exists' });

  const hash = hashPassword(password);
  const studentCode = role === 'student' ? makeStudentCode() : null;
  const finalSubject = role === 'teacher' ? (subject || 'General') : null;
  const finalPseudonym = role === 'teacher' ? (pseudonym || name) : null;

  const result = run(
    `INSERT INTO users (role, email, password_hash, name, pseudonym, subject, student_code) VALUES (?,?,?,?,?,?,?)`,
    [role, cleanEmail, hash, name.trim(), finalPseudonym, finalSubject, studentCode]
  );
  const user = get('SELECT * FROM users WHERE id = ?', [result.lastInsertRowid]);

  if (role === 'teacher') {
    for (let d = 0; d < 7; d++) {
      run("INSERT OR IGNORE INTO availability (teacher_id, day_of_week, is_on, start_time, end_time) VALUES (?,?,0,'09:00','17:00')", [user.id, d]);
    }
  }

  const token = signToken({ id: user.id, role: user.role, email: user.email });
  send(res, 200, { token, user: publicUser(user) });
});

post_('/api/auth/login', async (req, res, params, body) => {
  const { email, password, role } = body || {};
  if (!email || !password) return send(res, 400, { error: 'Email and password required' });
  const user = get('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return send(res, 401, { error: 'Email and password do not match an account' });
  }
  if (role && user.role !== role) {
    return send(res, 401, { error: `That account is a ${user.role} account. Use the ${user.role} sign-in.` });
  }
  const token = signToken({ id: user.id, role: user.role, email: user.email });
  send(res, 200, { token, user: publicUser(user) });
});

get_('/api/auth/me', async (req, res, params, body, authPayload) => {
  if (!authPayload) return send(res, 401, { error: 'Not authenticated' });
  const user = get('SELECT * FROM users WHERE id = ?', [authPayload.id]);
  if (!user) return send(res, 404, { error: 'User not found' });
  send(res, 200, { user: publicUser(user) });
});

// ============================================================
// TEACHER ROUTES
// ============================================================
function requireTeacher(authPayload, res) {
  if (!authPayload) { send(res, 401, { error: 'Not authenticated' }); return false; }
  if (authPayload.role !== 'teacher') { send(res, 403, { error: 'Teacher account required' }); return false; }
  return true;
}
function requireStudent(authPayload, res) {
  if (!authPayload) { send(res, 401, { error: 'Not authenticated' }); return false; }
  if (authPayload.role !== 'student') { send(res, 403, { error: 'Student account required' }); return false; }
  return true;
}

get_('/api/teacher/classes', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const rows = all(
    `SELECT c.*, u.name as student_name, u.student_code
     FROM classes c JOIN users u ON u.id = c.student_id
     WHERE c.teacher_id = ? ORDER BY c.date, c.start_time`,
    [authPayload.id]
  );
  send(res, 200, { classes: rows });
});

post_('/api/teacher/classes/:id/status', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const { status } = body || {};
  if (!['pending', 'done', 'cancelled'].includes(status)) return send(res, 400, { error: 'Invalid status' });
  const cls = get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?', [params.id, authPayload.id]);
  if (!cls) return send(res, 404, { error: 'Class not found' });
  run('UPDATE classes SET status = ? WHERE id = ?', [status, cls.id]);
  send(res, 200, { ok: true });
});

get_('/api/teacher/availability', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const rows = all('SELECT * FROM availability WHERE teacher_id = ? ORDER BY day_of_week', [authPayload.id]);
  send(res, 200, { availability: rows });
});

post_('/api/teacher/availability', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const { day_of_week, is_on, start_time, end_time } = body || {};
  if (day_of_week === undefined) return send(res, 400, { error: 'day_of_week required' });
  run(
    `INSERT INTO availability (teacher_id, day_of_week, is_on, start_time, end_time)
     VALUES (?,?,?,?,?)
     ON CONFLICT(teacher_id, day_of_week) DO UPDATE SET is_on=excluded.is_on, start_time=excluded.start_time, end_time=excluded.end_time`,
    [authPayload.id, day_of_week, is_on ? 1 : 0, start_time || '09:00', end_time || '17:00']
  );
  send(res, 200, { ok: true });
});

get_('/api/teacher/conversations', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const rows = all(
    `SELECT conv.id, conv.student_id, u.name as student_name, u.student_code,
       (SELECT text FROM messages m WHERE m.conversation_id = conv.id ORDER BY m.id DESC LIMIT 1) as last_text,
       (SELECT created_at FROM messages m WHERE m.conversation_id = conv.id ORDER BY m.id DESC LIMIT 1) as last_time
     FROM conversations conv JOIN users u ON u.id = conv.student_id
     WHERE conv.teacher_id = ? ORDER BY last_time DESC`,
    [authPayload.id]
  );
  send(res, 200, { conversations: rows });
});

get_('/api/teacher/conversations/:id/messages', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const conv = get('SELECT * FROM conversations WHERE id = ? AND teacher_id = ?', [params.id, authPayload.id]);
  if (!conv) return send(res, 404, { error: 'Conversation not found' });
  const msgs = all('SELECT * FROM messages WHERE conversation_id = ? ORDER BY id', [conv.id]);
  send(res, 200, { messages: msgs });
});

post_('/api/teacher/conversations/:id/messages', async (req, res, params, body, authPayload) => {
  if (!requireTeacher(authPayload, res)) return;
  const { text } = body || {};
  if (!text || !text.trim()) return send(res, 400, { error: 'Message text required' });
  const conv = get('SELECT * FROM conversations WHERE id = ? AND teacher_id = ?', [params.id, authPayload.id]);
  if (!conv) return send(res, 404, { error: 'Conversation not found' });
  run('INSERT INTO messages (conversation_id, sender_role, text) VALUES (?,?,?)', [conv.id, 'teacher', text.trim()]);
  send(res, 200, { ok: true });
});

// ============================================================
// STUDENT ROUTES
// ============================================================
get_('/api/student/teachers', async (req, res, params, body, authPayload, query) => {
  if (!requireStudent(authPayload, res)) return;
  const subject = query.get('subject');
  let rows;
  if (subject && subject.trim()) {
    rows = all(`SELECT id, name, pseudonym, subject FROM users WHERE role='teacher' AND subject LIKE ?`, ['%' + subject.trim() + '%']);
  } else {
    rows = all(`SELECT id, name, pseudonym, subject FROM users WHERE role='teacher'`);
  }
  send(res, 200, { teachers: rows });
});

get_('/api/student/teachers/:id/slots', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const teacherId = Number(params.id);
  const teacher = get(`SELECT id, name, pseudonym, subject FROM users WHERE id = ? AND role='teacher'`, [teacherId]);
  if (!teacher) return send(res, 404, { error: 'Teacher not found' });

  const avail = all('SELECT * FROM availability WHERE teacher_id = ? AND is_on = 1', [teacherId]);
  const availByDow = {};
  avail.forEach(a => { availByDow[a.day_of_week] = a; });

  const booked = all(`SELECT date, start_time FROM classes WHERE teacher_id = ? AND status != 'cancelled'`, [teacherId]);
  const bookedSet = new Set(booked.map(b => b.date + '|' + b.start_time));

  const days = [];
  const today = new Date();
  for (let i = 0; i < 14; i++) {
    const d = new Date(today);
    d.setDate(today.getDate() + i);
    const dow = d.getDay();
    const a = availByDow[dow];
    if (!a) continue;
    const dateKey = d.toISOString().slice(0, 10);
    const sh = parseInt(a.start_time.split(':')[0], 10);
    const eh = parseInt(a.end_time.split(':')[0], 10);
    const slots = [];
    for (let h = sh; h < eh; h++) {
      const startStr = String(h).padStart(2, '0') + ':00';
      if (!bookedSet.has(dateKey + '|' + startStr)) {
        slots.push({ start: startStr, end: String(h + 1).padStart(2, '0') + ':00' });
      }
    }
    if (slots.length) days.push({ date: dateKey, dow, slots });
  }
  send(res, 200, { teacher, days });
});

post_('/api/student/bookings', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const { teacher_id, date, start_time, end_time, subject } = body || {};
  if (!teacher_id || !date || !start_time || !end_time) return send(res, 400, { error: 'Missing booking fields' });
  const teacher = get(`SELECT * FROM users WHERE id = ? AND role='teacher'`, [teacher_id]);
  if (!teacher) return send(res, 404, { error: 'Teacher not found' });

  const clash = get(`SELECT id FROM classes WHERE teacher_id = ? AND date = ? AND start_time = ? AND status != 'cancelled'`, [teacher_id, date, start_time]);
  if (clash) return send(res, 409, { error: 'That slot was just booked by someone else' });

  const result = run(
    `INSERT INTO classes (teacher_id, student_id, date, start_time, end_time, subject, status) VALUES (?,?,?,?,?,?,'pending')`,
    [teacher_id, authPayload.id, date, start_time, end_time, subject || teacher.subject]
  );
  run(`INSERT OR IGNORE INTO conversations (teacher_id, student_id) VALUES (?,?)`, [teacher_id, authPayload.id]);
  const cls = get('SELECT * FROM classes WHERE id = ?', [result.lastInsertRowid]);
  send(res, 200, { class: cls });
});

get_('/api/student/classes', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const rows = all(
    `SELECT c.*, u.pseudonym as teacher_pseudonym, u.subject as teacher_subject
     FROM classes c JOIN users u ON u.id = c.teacher_id
     WHERE c.student_id = ? ORDER BY c.date, c.start_time`,
    [authPayload.id]
  );
  send(res, 200, { classes: rows });
});

get_('/api/student/conversations', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const rows = all(
    `SELECT conv.id, conv.teacher_id, u.pseudonym as teacher_pseudonym, u.subject as teacher_subject,
       (SELECT text FROM messages m WHERE m.conversation_id = conv.id ORDER BY m.id DESC LIMIT 1) as last_text,
       (SELECT created_at FROM messages m WHERE m.conversation_id = conv.id ORDER BY m.id DESC LIMIT 1) as last_time
     FROM conversations conv JOIN users u ON u.id = conv.teacher_id
     WHERE conv.student_id = ? ORDER BY last_time DESC`,
    [authPayload.id]
  );
  send(res, 200, { conversations: rows });
});

get_('/api/student/conversations/:id/messages', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const conv = get('SELECT * FROM conversations WHERE id = ? AND student_id = ?', [params.id, authPayload.id]);
  if (!conv) return send(res, 404, { error: 'Conversation not found' });
  const msgs = all('SELECT * FROM messages WHERE conversation_id = ? ORDER BY id', [conv.id]);
  send(res, 200, { messages: msgs });
});

post_('/api/student/conversations/:id/messages', async (req, res, params, body, authPayload) => {
  if (!requireStudent(authPayload, res)) return;
  const { text } = body || {};
  if (!text || !text.trim()) return send(res, 400, { error: 'Message text required' });
  const conv = get('SELECT * FROM conversations WHERE id = ? AND student_id = ?', [params.id, authPayload.id]);
  if (!conv) return send(res, 404, { error: 'Conversation not found' });
  run('INSERT INTO messages (conversation_id, sender_role, text) VALUES (?,?,?)', [conv.id, 'student', text.trim()]);
  send(res, 200, { ok: true });
});

// ============================================================
// static file serving
// ============================================================
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };
function serveStatic(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.join(PUBLIC_DIR, urlPath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // SPA fallback
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data2);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ============================================================
// server
// ============================================================
const server = http.createServer(async (req, res) => {
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    const pathname = urlObj.pathname;

    if (!pathname.startsWith('/api/')) return serveStatic(req, res);

    const method = req.method;
    for (const route of routes) {
      if (route.method !== method) continue;
      const m = pathname.match(route.regex);
      if (!m) continue;
      const params = {};
      route.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1]); });
      const body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
      const authPayload = authUser(req);
      await route.fn(req, res, params, body, authPayload, urlObj.searchParams);
      return;
    }
    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`A2LLC Tutors server running on http://localhost:${PORT}`);
});
