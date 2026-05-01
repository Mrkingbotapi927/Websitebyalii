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

const JWT_SECRET = process.env.JWT_SECRET || 'telehost_super_secret_2024';
const PORT = process.env.PORT || 3000;

// Persistent data directory - Railway volume
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');

// Create directories
[DATA_DIR, UPLOAD_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// Database
const db = new Database(path.join(DATA_DIR, 'telehost.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
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
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const runningBots = {};

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Multer - accept ALL files, no restrictions
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOAD_DIR, String(req.userId));
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    try {
      const name = Buffer.from(file.originalname, 'latin1').toString('utf8');
      cb(null, name);
    } catch {
      cb(null, file.originalname);
    }
  }
});

const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token nahi hai, login karo' });
  try {
    const d = jwt.verify(token, JWT_SECRET);
    req.userId = d.id;
    req.username = d.username;
    // Verify user exists in DB
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(d.id);
    if (!user) return res.status(401).json({ error: 'User nahi mila, dobara login karo' });
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid hai, dobara login karo' });
  }
}

function getLanguage(filename) {
  if (filename.endsWith('.py')) return 'Python';
  if (filename.endsWith('.js')) return 'Node.js';
  if (filename.endsWith('.sh')) return 'Shell';
  if (filename === 'Dockerfile') return 'Docker';
  if (filename.endsWith('.txt')) return 'Text';
  if (filename.endsWith('.json')) return 'JSON';
  if (filename.endsWith('.zip')) return 'ZIP';
  return 'File';
}

function getRunCommand(filename, dirPath) {
  const reqFile = path.join(dirPath, 'requirements.txt');
  if (filename.endsWith('.py')) {
    if (fs.existsSync(reqFile)) {
      return { cmd: 'bash', args: [`pip install -r requirements.txt -q 2>&1 && python3 ${filename}`] };
    }
    return { cmd: 'python3', args: [filename] };
  }
  if (filename.endsWith('.js')) {
    const pkgFile = path.join(dirPath, 'package.json');
    if (fs.existsSync(pkgFile)) {
      return { cmd: 'bash', args: [`npm install -q 2>&1 && node ${filename}`] };
    }
    return { cmd: 'node', args: [filename] };
  }
  if (filename.endsWith('.sh')) return { cmd: 'bash', args: [filename] };
  return { cmd: 'python3', args: [filename] };
}

// ── AUTH ──────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username aur password dono chahiye' });
  if (username.length < 3) return res.status(400).json({ error: 'Username kam se kam 3 characters ka hona chahiye' });
  if (password.length < 6) return res.status(400).json({ error: 'Password kam se kam 6 characters ka hona chahiye' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username mein sirf letters, numbers aur _ allowed hain' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Yeh username already le liya gaya hai' });
  const hashed = bcrypt.hashSync(password, 10);
  const r = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashed);
  const token = jwt.sign({ id: r.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ success: true, token, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Sab fields bharo' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Username ya password galat hai' });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ success: true, token, username });
});

// Check token validity
app.get('/api/me', auth, (req, res) => {
  res.json({ success: true, username: req.username, userId: req.userId });
});

// ── FILES ──────────────────────────────────────────────

app.post('/api/files/upload', auth, upload.single('script'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File nahi mili' });
  res.json({ success: true, filename: req.file.filename, lang: getLanguage(req.file.filename) });
});

app.get('/api/files', auth, (req, res) => {
  const userDir = path.join(UPLOAD_DIR, String(req.userId));
  if (!fs.existsSync(userDir)) return res.json({ files: [] });
  try {
    const files = fs.readdirSync(userDir).map(f => {
      const stat = fs.statSync(path.join(userDir, f));
      const sz = stat.size;
      const size = sz < 1024 ? sz + ' B' : sz < 1048576 ? Math.round(sz / 1024) + ' KB' : (sz / 1048576).toFixed(1) + ' MB';
      return { name: f, size, lang: getLanguage(f), date: stat.mtime.toLocaleDateString('en-IN') };
    });
    res.json({ files });
  } catch (e) {
    res.json({ files: [] });
  }
});

app.delete('/api/files/:filename', auth, (req, res) => {
  const fp = path.join(UPLOAD_DIR, String(req.userId), req.params.filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File nahi mili' });
  fs.unlinkSync(fp);
  res.json({ success: true });
});

// ── BOT ──────────────────────────────────────────────

app.get('/api/bot', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.userId);
  if (!bot) return res.json({ bot: null });
  const isRunning = !!(runningBots[bot.id]) && bot.status === 'running';
  res.json({
    bot: {
      ...bot,
      status: isRunning ? 'running' : 'stopped',
      uptime: isRunning && bot.started_at ? Math.floor(Date.now() / 1000) - bot.started_at : 0
    }
  });
});

function startBotProcess(botId, userId, cmd, args, userDir) {
  const proc = spawn(cmd, args, { cwd: userDir, shell: true });
  db.prepare('UPDATE bots SET pid=? WHERE id=?').run(proc.pid, botId);
  runningBots[botId] = { process: proc, userId, wsClients: new Set() };

  const broadcast = (msg) => {
    if (!runningBots[botId]) return;
    runningBots[botId].wsClients.forEach(ws => {
      try { if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'log', data: msg })); } catch {}
    });
  };

  proc.stdout.on('data', d => broadcast(d.toString()));
  proc.stderr.on('data', d => broadcast('[ERR] ' + d.toString()));
  proc.on('close', code => {
    broadcast(`[SYSTEM] Bot band ho gaya — exit code: ${code}`);
    try { db.prepare('UPDATE bots SET status=?, pid=NULL WHERE id=?').run('stopped', botId); } catch {}
    delete runningBots[botId];
  });
  proc.on('error', err => {
    broadcast(`[ERR] Bot start nahi hua: ${err.message}`);
    try { db.prepare('UPDATE bots SET status=?, pid=NULL WHERE id=?').run('stopped', botId); } catch {}
    delete runningBots[botId];
  });

  // RAM simulation
  const ri = setInterval(() => {
    if (!runningBots[botId]) { clearInterval(ri); return; }
    const ram = Math.floor(60 + Math.random() * 120);
    try { db.prepare('UPDATE bots SET ram_used=? WHERE id=?').run(ram, botId); } catch {}
  }, 10000);
}

app.post('/api/bot/run', auth, (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'Filename chahiye' });

  // Stop existing running bot
  const existingBot = db.prepare('SELECT * FROM bots WHERE user_id=? AND status=?').get(req.userId, 'running');
  if (existingBot && runningBots[existingBot.id]) {
    try { treeKill(runningBots[existingBot.id].process.pid, 'SIGKILL'); } catch {}
    delete runningBots[existingBot.id];
    db.prepare('UPDATE bots SET status=?, pid=NULL WHERE id=?').run('stopped', existingBot.id);
  }

  const userDir = path.join(UPLOAD_DIR, String(req.userId));
  const filepath = path.join(userDir, filename);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File nahi mili. Pehle upload karo.' });

  const lang = getLanguage(filename);
  const { cmd, args } = getRunCommand(filename, userDir);

  let botId;
  const existing = db.prepare('SELECT id FROM bots WHERE user_id=? AND filename=?').get(req.userId, filename);
  if (existing) {
    db.prepare('UPDATE bots SET status=?, started_at=?, pid=NULL, restarts=restarts+1, filepath=?, language=? WHERE id=?')
      .run('running', Math.floor(Date.now() / 1000), filepath, lang, existing.id);
    botId = existing.id;
  } else {
    const r = db.prepare('INSERT INTO bots (user_id,filename,filepath,language,status,started_at) VALUES (?,?,?,?,?,?)')
      .run(req.userId, filename, filepath, lang, 'running', Math.floor(Date.now() / 1000));
    botId = r.lastInsertRowid;
  }

  startBotProcess(botId, req.userId, cmd, args, userDir);
  res.json({ success: true, botId });
});

app.post('/api/bot/stop', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id=? AND status=?').get(req.userId, 'running');
  if (!bot) return res.status(404).json({ error: 'Koi bot nahi chal raha' });
  if (runningBots[bot.id]) {
    try { treeKill(runningBots[bot.id].process.pid, 'SIGKILL'); } catch {}
    delete runningBots[bot.id];
  }
  db.prepare('UPDATE bots SET status=?, pid=NULL WHERE id=?').run('stopped', bot.id);
  res.json({ success: true });
});

app.post('/api/bot/restart', auth, (req, res) => {
  const bot = db.prepare('SELECT * FROM bots WHERE user_id=? ORDER BY id DESC LIMIT 1').get(req.userId);
  if (!bot) return res.status(404).json({ error: 'Koi bot nahi mila' });
  if (runningBots[bot.id]) {
    try { treeKill(runningBots[bot.id].process.pid, 'SIGKILL'); } catch {}
    delete runningBots[bot.id];
  }
  if (!fs.existsSync(bot.filepath)) return res.status(404).json({ error: 'Script file nahi mili server pe' });
  const userDir = path.dirname(bot.filepath);
  const { cmd, args } = getRunCommand(bot.filename, userDir);
  db.prepare('UPDATE bots SET status=?, started_at=?, restarts=restarts+1 WHERE id=?')
    .run('running', Math.floor(Date.now() / 1000), bot.id);
  startBotProcess(bot.id, req.userId, cmd, args, userDir);
  res.json({ success: true });
});

// ── WEBSOCKET ──────────────────────────────────────────

wss.on('connection', (ws, req) => {
  const params = new URLSearchParams(req.url.replace('/?', '').replace('/', ''));
  const token = params.get('token');
  const botId = parseInt(params.get('botId'));
  if (!token || !botId) { ws.close(); return; }
  let userId;
  try { userId = jwt.verify(token, JWT_SECRET).id; } catch { ws.close(); return; }
  if (runningBots[botId] && runningBots[botId].userId === userId) {
    runningBots[botId].wsClients.add(ws);
    ws.send(JSON.stringify({ type: 'log', data: '[SYSTEM] Live logs se connect ho gaya! ✅\n' }));
  } else {
    ws.send(JSON.stringify({ type: 'log', data: '[SYSTEM] Bot abhi chal nahi raha.\n' }));
  }
  ws.on('close', () => { if (runningBots[botId]) runningBots[botId].wsClients.delete(ws); });
});

// Serve HTML files
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send('TeleHost - Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 TeleHost running on port ${PORT}`);
  console.log(`📁 Data dir: ${DATA_DIR}`);
  console.log(`📦 Upload dir: ${UPLOAD_DIR}`);
});
