require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, 'secureline.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function signToken(user){
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'Login required' });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  }catch(e){
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function publicUser(u){
  return { id: u.id, username: u.username, publicKey: u.public_key };
}

app.post('/api/auth/signup', async (req, res) => {
  try{
    const { username, email, phone, password, publicKey } = req.body || {};

    if(!username || !password || !publicKey){
      return res.status(400).json({ error: 'username, password, aur publicKey zaroori hain' });
    }
    if(!email && !phone){
      return res.status(400).json({ error: 'Email ya phone me se ek dena zaroori hai' });
    }
    if(!/^[a-zA-Z0-9_.]{3,20}$/.test(username)){
      return res.status(400).json({ error: 'Username sirf letters/numbers/underscore, 3-20 characters' });
    }
    if(password.length < 6){
      return res.status(400).json({ error: 'Password kam se kam 6 characters ka ho' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if(existing) return res.status(409).json({ error: 'Ye username pehle se liya gaya hai' });

    if(email){
      const e = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if(e) return res.status(409).json({ error: 'Is email se pehle se account hai' });
    }
    if(phone){
      const p = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
      if(p) return res.status(409).json({ error: 'Is phone se pehle se account hai' });
    }

    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare(
      `INSERT INTO users (username, email, phone, password_hash, public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(username, email || null, phone || null, hash, publicKey, Date.now());

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    return res.json({ token: signToken(user), user: publicUser(user) });
  }catch(e){
    console.error(e);
    return res.status(500).json({ error: 'Signup fail hui, dobara try karo' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try{
    const { identifier, password } = req.body || {};
    if(!identifier || !password) return res.status(400).json({ error: 'Username/email/phone aur password chahiye' });

    const user = db.prepare(
      'SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?'
    ).get(identifier, identifier, identifier);

    if(!user) return res.status(401).json({ error: 'Account nahi mila' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ error: 'Galat password' });

    return res.json({ token: signToken(user), user: publicUser(user) });
  }catch(e){
    console.error(e);
    return res.status(500).json({ error: 'Login fail hui, dobara try karo' });
  }
});

app.get('/api/users/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if(!user) return res.status(404).json({ error: 'User nahi mila' });
  res.json({ user: publicUser(user) });
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').trim();
  if(q.length < 1) return res.json({ users: [] });
  const rows = db.prepare(
    `SELECT * FROM users WHERE username LIKE ? AND id != ? ORDER BY username LIMIT 20`
  ).all(q + '%', req.user.id);
  res.json({ users: rows.map(publicUser) });
});

app.get('/api/users/by-username/:username', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.username);
  if(!u) return res.status(404).json({ error: 'User nahi mila' });
  res.json({ user: publicUser(u) });
});

app.get('/api/conversations', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT u.username, u.public_key,
      (SELECT MAX(created_at) FROM messages m2
        WHERE (m2.sender_id = ? AND m2.recipient_id = u.id)
           OR (m2.sender_id = u.id AND m2.recipient_id = ?)) AS last_ts
    FROM users u
    WHERE u.id IN (
      SELECT sender_id FROM messages WHERE recipient_id = ?
      UNION
      SELECT recipient_id FROM messages WHERE sender_id = ?
    )
    ORDER BY last_ts DESC
  `).all(req.user.id, req.user.id, req.user.id, req.user.id);
  res.json({ conversations: rows });
});

app.get('/api/messages/:username', authMiddleware, (req, res) => {
  const other = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.username);
  if(!other) return res.status(404).json({ error: 'User nahi mila' });

  const rows = db.prepare(`
    SELECT m.*, su.username AS sender_username FROM messages m
    JOIN users su ON su.id = m.sender_id
    WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
    ORDER BY m.created_at ASC
    LIMIT 500
  `).all(req.user.id, other.id, other.id, req.user.id);

  res.json({ messages: rows.map(r => ({
    id: r.id, from: r.sender_username, iv: r.iv, ciphertext: r.ciphertext, ts: r.created_at
  })) });
});

app.post('/api/messages/:username', authMiddleware, (req, res) => {
  const other = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.username);
  if(!other) return res.status(404).json({ error: 'User nahi mila' });

  const { iv, ciphertext } = req.body || {};
  if(!iv || !ciphertext) return res.status(400).json({ error: 'iv aur ciphertext chahiye' });

  const ts = Date.now();
  const info = db.prepare(
    `INSERT INTO messages (sender_id, recipient_id, iv, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)`
  ).run(req.user.id, other.id, iv, ciphertext, ts);

  const payload = { id: info.lastInsertRowid, from: req.user.username, iv, ciphertext, ts };
  pushToUser(other.id, { type: 'message', ...payload, otherUsername: req.user.username });
  pushToUser(req.user.id, { type: 'message_sent', ...payload, otherUsername: other.username });

  res.json({ message: payload });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const socketsByUser = new Map();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  let userId = null;
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    userId = payload.id;
  }catch(e){
    ws.close(4001, 'Invalid token');
    return;
  }
  if(!socketsByUser.has(userId)) socketsByUser.set(userId, new Set());
  socketsByUser.get(userId).add(ws);

  ws.on('close', () => {
    const set = socketsByUser.get(userId);
    if(set){ set.delete(ws); if(set.size === 0) socketsByUser.delete(userId); }
  });
});

function pushToUser(userId, data){
  const set = socketsByUser.get(userId);
  if(!set) return;
  const msg = JSON.stringify(data);
  set.forEach(ws => { if(ws.readyState === 1) ws.send(msg); });
}

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`SecureLine server running on port ${PORT}`);
});
