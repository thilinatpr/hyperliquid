const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const express = require('express');
const session = require('express-session');
const db = require('./db');
const http = require('http');
const { Server } = require('socket.io');
const { ethers } = require('ethers');
const { startMonitoring } = require('./fillMonitor');


const app = express();
app.use(express.json());

// SESSION SETUP
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_with_strong_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // For HTTP; set true with HTTPS
}));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// IN-MEMORY NONCES FOR LOGIN SIGNING (ETH address => { nonce, timestamp })
const nonces = new Map();

// TEST USER ETH ADDRESS SIMULATION
const TEST_USER_ETH_ADDRESS = 'testUser';

// CLEANUP EXPIRED NONCES EVERY MINUTE
setInterval(() => {
  const now = Date.now();
  for (const [address, { timestamp }] of nonces.entries()) {
    // 5 minutes expiry
    if (now - timestamp > 5 * 60 * 1000) {
      nonces.delete(address);
    }
  }
}, 60 * 1000);

// GENERATE NONCE FOR CLIENT TO SIGN
app.get('/api/nonce/:address', (req, res) => {
  const address = req.params.address.toLowerCase();

  if (!ethers.isAddress(address)) {
    return res.status(400).json({ error: 'Invalid Ethereum address' });
  }

  // Generate a secure nonce with large random number
  const nonce = `Login nonce: ${Math.floor(Math.random() * 1_000_000_000_000)}`;

  nonces.set(address, { nonce, timestamp: Date.now() });

  res.json({ nonce });
});

// LOGIN WITH METAMASK SIGNATURE
app.post('/api/login-metamask', async (req, res) => {
  try {
    let { address, signature } = req.body;
    if (!address || !signature) {
      return res.status(400).json({ error: 'Address and signature required' });
    }

    address = address.toLowerCase();

    if (!ethers.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }

    const stored = nonces.get(address);
    if (!stored) {
      return res.status(400).json({ error: 'Nonce not found or expired. Request a new nonce.' });
    }

    const message = stored.nonce;

    // Recover address from signature
    const recoveredAddress = ethers.verifyMessage(message, signature).toLowerCase();

    if (recoveredAddress !== address) {
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    // Valid signature - create session
    req.session.ethAddress = address;

    // Remove nonce after use to avoid replay
    nonces.delete(address);

    res.json({ message: 'Logged in successfully' });
  } catch (error) {
    console.error('MetaMask login error:', error);
    res.status(500).json({ error: 'Server error during MetaMask login' });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Error logging out' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

// TEST LOGIN (non MetaMask)
app.post('/api/test-login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'admin') {
    req.session.testUser = true;
    return res.json({ message: 'Test login successful' });
  }
  return res.status(401).json({ error: 'Invalid username or password' });
});

// AUTH MIDDLEWARE
function isTestOrEthAuthenticated(req, res, next) {
  if (req.session && (req.session.ethAddress || req.session.testUser)) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// ACTIVE MONITORS MAP: ethAddress/testUser => monitorInstance
const activeMonitors = new Map();

// SAVE CONFIG & START MONITORING
app.post('/api/setConfig', isTestOrEthAuthenticated, (req, res) => {
  let ethAddress;
  if (req.session.testUser) {
    ethAddress = TEST_USER_ETH_ADDRESS;
  } else {
    ethAddress = req.session.ethAddress;
  }

  const {
    privateKey,
    walletAddress,
    webhookUrl,
    tokens,
    minSize
  } = req.body;

  // VALIDATION
  if (!privateKey || !privateKey.startsWith('0x') || privateKey.length < 66) {
    return res.status(400).json({ error: 'Invalid private key format' });
  }
  if (!walletAddress || !walletAddress.startsWith('0x') || walletAddress.length !== 42) {
    return res.status(400).json({ error: 'Invalid wallet address format' });
  }
  if (!webhookUrl || !webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
    return res.status(400).json({ error: 'Invalid Discord webhook URL' });
  }
  if (!Array.isArray(tokens) || tokens.length === 0 || !tokens.every(t => typeof t === 'string' && t.trim().length > 0)) {
    return res.status(400).json({ error: 'Tokens must be a non-empty array of strings' });
  }
  if (typeof minSize !== 'number' || minSize <= 0) {
    return res.status(400).json({ error: 'minSize must be a positive number' });
  }

  try {
    const tokensStr = JSON.stringify(tokens.map(t => t.trim().toUpperCase()));

    const exists = db.prepare('SELECT 1 FROM configs WHERE ethAddress = ?').get(ethAddress);
    if (exists) {
      db.prepare(`
        UPDATE configs
        SET privateKey = ?, walletAddress = ?, webhookUrl = ?, tokens = ?, minSize = ?, is_active = 1
        WHERE ethAddress = ?
      `).run(privateKey, walletAddress, webhookUrl, tokensStr, minSize, ethAddress);
    } else {
      db.prepare(`
        INSERT INTO configs (ethAddress, privateKey, walletAddress, webhookUrl, tokens, minSize, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(ethAddress, privateKey, walletAddress, webhookUrl, tokensStr, minSize);
    }

    // Stop existing monitor if any
    if (activeMonitors.has(ethAddress)) {
      const oldMonitor = activeMonitors.get(ethAddress);
      if (oldMonitor && oldMonitor.wsInstance) {
        oldMonitor.wsInstance.close();
      }
    }

    // Start new monitor instance
    const monitorInstance = startMonitoring(io, { privateKey, walletAddress, webhookUrl, tokens: JSON.parse(tokensStr), minSize });
    activeMonitors.set(ethAddress, monitorInstance);

    res.json({ message: 'Configuration saved and monitoring started' });
  } catch (error) {
    console.error('Failed to save config or start monitoring:', error);
    res.status(500).json({ error: 'Failed to save config or start monitoring' });
  }
});

// GET CONFIG FOR CURRENT USER
app.get('/api/getConfig', isTestOrEthAuthenticated, (req, res) => {
  let ethAddress;
  if (req.session.testUser) {
    ethAddress = TEST_USER_ETH_ADDRESS;
  } else {
    ethAddress = req.session.ethAddress;
  }

  try {
    const row = db.prepare('SELECT privateKey, walletAddress, webhookUrl, tokens, minSize FROM configs WHERE ethAddress = ?').get(ethAddress);
    if (!row) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    let tokens = [];
    try {
      tokens = JSON.parse(row.tokens);
    } catch { /* ignore parse errors */ }
    res.json({
      privateKey: row.privateKey,
      walletAddress: row.walletAddress,
      webhookUrl: row.webhookUrl,
      tokens,
      minSize: row.minSize
    });
  } catch (error) {
    console.error('Failed to load config:', error);
    res.status(500).json({ error: 'Failed to load config' });
  }
});

// STOP TRACKING CURRENT USER
app.post('/api/stopTracking', isTestOrEthAuthenticated, (req, res) => {
  let ethAddress;
  if (req.session.testUser) {
    ethAddress = TEST_USER_ETH_ADDRESS;
  } else {
    ethAddress = req.session.ethAddress;
  }

  if (activeMonitors.has(ethAddress)) {
    const monitorInstance = activeMonitors.get(ethAddress);
    if (monitorInstance && monitorInstance.wsInstance) {
      monitorInstance.wsInstance.close();
    }
    activeMonitors.delete(ethAddress);
  }

  db.prepare('UPDATE configs SET is_active = 0 WHERE ethAddress = ?').run(ethAddress);

  res.json({ message: 'Monitoring stopped' });
});

// PROTECT ADMIN PAGE (admin.html) FOR AUTHENTICATED USERS ONLY
app.use((req, res, next) => {
  if (req.path === '/admin.html') {
    if (req.session && (req.session.ethAddress || req.session.testUser)) {
      next();
    } else {
      // Redirect unauthorized users to login page
      return res.redirect('/test-login.html');
    }
  } else {
    next();
  }
});

// RESTORE ACTIVE MONITORS ON STARTUP
function restoreActiveMonitors() {
  try {
    const rows = db.prepare('SELECT privateKey, walletAddress, webhookUrl, tokens, minSize, ethAddress FROM configs WHERE is_active = 1').all();

    for (const row of rows) {
      let tokens = [];
      try {
        tokens = JSON.parse(row.tokens);
      } catch { /* Ignore */ }

      const config = {
        privateKey: row.privateKey,
        walletAddress: row.walletAddress,
        webhookUrl: row.webhookUrl,
        tokens,
        minSize: row.minSize
      };

      try {
        const monitorInstance = startMonitoring(io, config);
        activeMonitors.set(row.ethAddress, monitorInstance);
        console.log(`✅ Restored monitoring for ethAddress ${row.ethAddress}`);
      } catch (err) {
        console.error(`Failed to restore monitor for ethAddress ${row.ethAddress}:`, err);
      }
    }
  } catch (err) {
    console.error('Error restoring active monitors:', err);
  }
}

restoreActiveMonitors();

// SERVE STATIC FILES FROM 'public' FOLDER
app.use(express.static(path.resolve(__dirname, '../public')));

// HEALTH CHECK ENDPOINT
app.get('/health', (req, res) => res.status(200).send('OK'));

// SOCKET.IO CONNECTION
io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });

  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// SERVER ERROR HANDLING AND PORT REUSE
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

server.on('error', (error) => {
  console.error('Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Trying again in 5 seconds...`);
    setTimeout(() => {
      server.close();
      server.listen(PORT);
    }, 5000);
  }
});

// HANDLE PROCESS EVENTS

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  // Force shutdown after 10s
  setTimeout(() => {
    console.error('Forcing server close after timeout');
    process.exit(1);
  }, 10000);
});
