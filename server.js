const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const treeKill = require('tree-kill');
const path = require('path');
const fs = require('fs');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'telehost_secret_key_2024';
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DB_PATH = path.join(__dirname, 'telehost.db');

// Create uploads dir
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Database setup
const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    ram_limit INTEGER DEFAULT 500
  );
  CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    language TEXT NOT NULL,
    status TEXT DEFAULT 'stopped',
    pid INTEGER,
    started_at INTEGER,
    restarts INTEGER DEFAULT 0,
    ram_used INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Store running processes in memory
const runningBots = {}; // { botId: { process, userId, wsClients: Set } }

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOAD_DIR, String(req.userId));
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    if (file.originalname.endsWith('.py') || file.originalname.endsWith('.js')) cb(null, true);
    else cb(new Error('Only .py and .js files allowed'));
  }
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── AUTH ROUTES ───────────────────────────────────────

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username too short' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const hashed = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashed);
  const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, username });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Fill all fields' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, username });
});

// ─── FILE ROUTES ────────────────────────────────────────

// Upload file
app.post('/api/files/upload', auth, upload.single('script'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const lang = req.file.originalname.endsWith('.py') ? 'Python' : 'Node.js';
  res.json({ success: true, filename: req.file.originalname, lang });
});

// List files
app.get('/api/files', auth, (req, res) => {
  const userDir = path.join(UPLOAD_DIR, String(req.userId));
  if (!fs.existsSync(userDir)) return res.json({ files: [] });
  const files = fs.readdirSync(userDir)
    .filter(f => f.endsWith('.py') || f.endsWith('.js'))
    .map(f => {
      const stat = fs.statSync(path.join(userDir, f));
      const size = stat.size < 1024 ? stat.size + ' B' : Math.round(stat.size / 1024) + ' KB';
      return { name: f, size, lang: f.endsWith('.py') ? 'Python' : 'Node.js', date: stat.mtime.toLocaleDateString() };
    });
  res.json({ files });
});

// Delete file
app.delete('/api/files/:filename', auth, (req, res) => {
  const filepath = path.join(UPLOAD_DIR, String(req.userId), req.params.filename);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
  fs.unlinkSync(filepath);
  res.json({ success: true });
});

// ─── BOT ROUTES ─────────────────────────────────────────

// Get bot status
app.get('/api/bot', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.userId);
  if (!bot) return res.json({ bot: null });

  const isRunning = runningBots[bot.id] && bot.status === 'running';
  res.json({
    bot: {
      ...bot,
      status: isRunning ? 'running' : 'stopped',
      uptime: isRunning && bot.started_at ? Math.floor((Date.now()/1000) - bot.started_at) : 0
    }
  });
});

// Run bot
app.post('/api/bot/run', auth, (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'Filename required' });

  // Stop existing bot
  const existingBot = db.prepare('SELECT * FROM bots WHERE user_id = ? AND status = ?').get(req.userId, 'running');
  if (existingBot && runningBots[existingBot.id]) {
    treeKill(runningBots[existingBot.id].process.pid, 'SIGKILL');
    delete runningBots[existingBot.id];
    db.prepare('UPDATE bots SET status = ?, pid = NULL WHERE id = ?').run('stopped', existingBot.id);
  }

  const filepath = path.join(UPLOAD_DIR, String(req.userId), filename);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });

  const lang = filename.endsWith('.py') ? 'Python' : 'Node.js';
  const cmd = filename.endsWith('.py') ? 'python3' : 'node';

  // Create or update bot record
  let botId;
  const existing = db.prepare('SELECT id FROM bots WHERE user_id = ? AND filename = ?').get(req.userId, filename);
  if (existing) {
    db.prepare('UPDATE bots SET status = ?, started_at = ?, pid = NULL, restarts = restarts + 1, filepath = ? WHERE id = ?')
      .run('running', Math.floor(Date.now()/1000), filepath, existing.id);
    botId = existing.id;
  } else {
    const r = db.prepare('INSERT INTO bots (user_id, filename, filepath, language, status, started_at) VALUES (?,?,?,?,?,?)')
      .run(req.userId, filename, filepath, lang, 'running', Math.floor(Date.now()/1000));
    botId = r.lastInsertRowid;
  }

  // Spawn process
  const proc = spawn(cmd, [filepath], { cwd: path.join(UPLOAD_DIR, String(req.userId)) });
  db.prepare('UPDATE bots SET pid = ? WHERE id = ?').run(proc.pid, botId);

  runningBots[botId] = { process: proc, userId: req.userId, wsClients: new Set() };

  const broadcast = (msg) => {
    if (!runningBots[botId]) return;
    runningBots[botId].wsClients.forEach(ws => {
      if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'log', data: msg }));
    });
  };

  proc.stdout.on('data', d => broadcast(d.toString()));
  proc.stderr.on('data', d => broadcast('[ERR] ' + d.toString()));
  proc.on('close', code => {
    broadcast('[SYSTEM] Bot process exited with code ' + code);
    db.prepare('UPDATE bots SET status = ?, pid = NULL WHERE id = ?').run('stopped', botId);
    delete runningBots[botId];
  });

  // Fake RAM usage (update every 10s)
  const ramInterval = setInterval(() => {
    if (!runningBots[botId]) { clearInterval(ramInterval); return; }
    const ram = Math.floor(80 + Math.random() * 100);
    db.prepare('UPDATE bots SET ram_used = ? WHERE id = ?').run(ram, botId);
  }, 10000);

  res.json({ success: true, botId, pid: proc.pid });
});

// Stop bot
app.post('/api/bot/stop', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id = ? AND status = ?').get(req.userId, 'running');
  if (!bot) return res.status(404).json({ error: 'No running bot' });

  if (runningBots[bot.id]) {
    treeKill(runningBots[bot.id].process.pid, 'SIGKILL');
    delete runningBots[bot.id];
  }
  db.prepare('UPDATE bots SET status = ?, pid = NULL WHERE id = ?').run('stopped', bot.id);
  res.json({ success: true });
});

// Restart bot
app.post('/api/bot/restart', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.userId);
  if (!bot) return res.status(404).json({ error: 'No bot found' });

  // Stop
  if (runningBots[bot.id]) {
    treeKill(runningBots[bot.id].process.pid, 'SIGKILL');
    delete runningBots[bot.id];
  }

  // Restart via same run logic
  req.body = { filename: bot.filename };
  // Manually re-run
  const filepath = bot.filepath;
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'Script file not found' });

  const cmd = bot.filename.endsWith('.py') ? 'python3' : 'node';
  db.prepare('UPDATE bots SET status = ?, started_at = ?, restarts = restarts + 1 WHERE id = ?')
    .run('running', Math.floor(Date.now()/1000), bot.id);

  const proc = spawn(cmd, [filepath], { cwd: path.dirname(filepath) });
  db.prepare('UPDATE bots SET pid = ? WHERE id = ?').run(proc.pid, bot.id);
  runningBots[bot.id] = { process: proc, userId: req.userId, wsClients: new Set() };

  proc.stdout.on('data', d => {
    if (runningBots[bot.id]) runningBots[bot.id].wsClients.forEach(ws => { if(ws.readyState===1) ws.send(JSON.stringify({type:'log',data:d.toString()})); });
  });
  proc.stderr.on('data', d => {
    if (runningBots[bot.id]) runningBots[bot.id].wsClients.forEach(ws => { if(ws.readyState===1) ws.send(JSON.stringify({type:'log',data:'[ERR] '+d.toString()})); });
  });
  proc.on('close', code => {
    db.prepare('UPDATE bots SET status = ?, pid = NULL WHERE id = ?').run('stopped', bot.id);
    delete runningBots[bot.id];
  });

  res.json({ success: true });
});

// ─── WEBSOCKET (Live Logs) ───────────────────────────────

wss.on('connection', (ws, req) => {
  const params = new URLSearchParams(req.url.replace('/?', ''));
  const token = params.get('token');
  const botId = parseInt(params.get('botId'));

  let userId;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    userId = decoded.id;
  } catch {
    ws.close();
    return;
  }

  if (runningBots[botId] && runningBots[botId].userId === userId) {
    runningBots[botId].wsClients.add(ws);
    ws.send(JSON.stringify({ type: 'log', data: '[SYSTEM] Connected to live logs...\n' }));
  }

  ws.on('close', () => {
    if (runningBots[botId]) runningBots[botId].wsClients.delete(ws);
  });
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`TeleHost running on port ${PORT}`);
});
