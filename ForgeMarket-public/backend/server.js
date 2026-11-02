'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const {
  randomBytes,
  scrypt: scryptCallback,
  timingSafeEqual,
} = require('node:crypto');

const scrypt = promisify(scryptCallback);
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 8192;
const HTML_FILE = path.join(__dirname, '..', 'Raw Material Market Place.html');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.jsonl');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.jsonl');
const PRODUCT_CATALOG = [
  { id: 0, name: '304 Stainless Steel Sheet', priceInr: 3552.40, unit: 'sheet' },
  { id: 1, name: 'Aluminum 6061-T6 Bar', priceInr: 1535.50, unit: 'kg' },
  { id: 2, name: 'HDPE Resin Pellets', priceInr: 178.45, unit: 'kg' },
  { id: 3, name: 'Industrial Epoxy Resin', priceInr: 7138, unit: 'kit' },
  { id: 4, name: 'Portland Cement Type I', priceInr: 726.25, unit: 'bag' },
  { id: 5, name: 'Corrugated Shipping Cartons', priceInr: 76.36, unit: 'unit' },
  { id: 6, name: 'Fe 500D TMT Rebar', priceInr: 58, unit: 'kg' },
  { id: 7, name: 'Copper Wire Rod', priceInr: 890, unit: 'kg' },
  { id: 8, name: 'PP Homopolymer Granules', priceInr: 105, unit: 'kg' },
  { id: 9, name: 'Natural Rubber RSS-4', priceInr: 205, unit: 'kg' },
  { id: 10, name: 'Caustic Soda Flakes', priceInr: 52, unit: 'kg' },
  { id: 11, name: 'OPC 53 Grade Cement', priceInr: 430, unit: 'bag' },
  { id: 12, name: 'BOPP Packaging Film', priceInr: 165, unit: 'kg' },
  { id: 13, name: 'Shankar-6 Cotton Lint', priceInr: 62, unit: 'kg' },
  { id: 14, name: 'Coir Fibre', priceInr: 38, unit: 'kg' },
];
const users = new Map();
const sessions = new Map();
const authAttempts = new Map();

function loadUsers() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) return;

  const contents = fs.readFileSync(USERS_FILE, 'utf8');
  for (const [index, line] of contents.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    let user;
    try {
      user = JSON.parse(line);
    } catch (error) {
      throw new Error(`Could not read account data at line ${index + 1}: ${error.message}`);
    }
    if (!user.email || !user.name || !user.salt || !user.passwordHash) {
      throw new Error(`Account data at line ${index + 1} is incomplete.`);
    }
    users.set(user.email, user);
  }
}

function sendJson(response, status, body, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  response.end(JSON.stringify(body));
}

function setSessionCookie(response, token, maxAge = SESSION_TTL_MS / 1000) {
  response.setHeader(
    'Set-Cookie',
    `forgemarket_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`,
  );
}

function clearSessionCookie(response) {
  setSessionCookie(response, '', 0);
}

function getSession(request) {
  const cookie = request.headers.cookie || '';
  const token = cookie.match(/(?:^|;\s*)forgemarket_session=([A-Za-z0-9_-]+)/)?.[1];
  if (!token) return null;

  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, session };
}

function publicUser(user) {
  return { name: user.name, email: user.email };
}

function checkSameOrigin(request, response) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const parsedOrigin = new URL(origin);
    if (parsedOrigin.protocol === 'http:' && parsedOrigin.host === request.headers.host) return true;
  } catch {
    // A malformed Origin header is rejected below.
  }
  sendJson(response, 403, { error: 'Request origin is not allowed.' });
  return false;
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    request.setEncoding('utf8');
    request.on('data', chunk => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Request is too large.'), { status: 413 }));
        request.resume();
        return;
      }
      body += chunk;
    });
    request.on('end', () => {
      if (size > MAX_BODY_BYTES) return;
      try {
        resolve(JSON.parse(body || '{}'));
      } catch {
        reject(Object.assign(new Error('Request body must be valid JSON.'), { status: 400 }));
      }
    });
    request.on('error', reject);
  });
}

function getAuthRateLimit(request) {
  const address = request.socket.remoteAddress || 'local';
  const now = Date.now();
  const entry = authAttempts.get(address);
  if (!entry || entry.resetAt <= now) {
    const fresh = { count: 1, resetAt: now + 15 * 60 * 1000 };
    authAttempts.set(address, fresh);
    return fresh.count <= 10;
  }
  entry.count += 1;
  return entry.count <= 10;
}

function normalizeCredentials(input, isSignup) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'Please provide your account details.' };
  }
  if (typeof input.email !== 'string' || typeof input.password !== 'string') {
    return { error: 'Please enter a valid email address and password.' };
  }

  const email = input.email.trim().toLowerCase();
  const password = input.password;
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { error: 'Please enter a valid email address.' };
  }
  if (password.length > 128 || password.length < (isSignup ? 8 : 1)) {
    return { error: isSignup ? 'Password must be between 8 and 128 characters.' : 'Please enter your password.' };
  }

  if (!isSignup) return { email, password };
  if (typeof input.name !== 'string') return { error: 'Please enter your name.' };
  const name = input.name.trim();
  if (!name || name.length > 80) return { error: 'Name must be between 1 and 80 characters.' };
  return { email, password, name };
}

function issueSession(response, user) {
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, { email: user.email, expiresAt: Date.now() + SESSION_TTL_MS });
  setSessionCookie(response, token);
  sendJson(response, 200, { user: publicUser(user) });
}

async function handleAuth(request, response, route) {
  if (!checkSameOrigin(request, response)) return;
  const contentType = request.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    sendJson(response, 415, { error: 'Content-Type must be application/json.' });
    return;
  }
  if (!getAuthRateLimit(request)) {
    sendJson(response, 429, { error: 'Too many attempts. Please wait 15 minutes and try again.' });
    return;
  }

  const input = await readJson(request);
  const isSignup = route === '/api/signup';
  const credentials = normalizeCredentials(input, isSignup);
  if (credentials.error) {
    sendJson(response, 400, { error: credentials.error });
    return;
  }

  if (isSignup) {
    if (users.has(credentials.email)) {
      sendJson(response, 409, { error: 'An account with that email already exists.' });
      return;
    }
    const salt = randomBytes(16);
    const derivedKey = await scrypt(credentials.password, salt, 64, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
    const user = {
      email: credentials.email,
      name: credentials.name,
      salt: salt.toString('base64'),
      passwordHash: derivedKey.toString('base64'),
    };
    fs.appendFileSync(USERS_FILE, `${JSON.stringify(user)}\n`, { encoding: 'utf8', mode: 0o600 });
    users.set(user.email, user);
    issueSession(response, user);
    return;
  }

  const user = users.get(credentials.email);
  const salt = user ? Buffer.from(user.salt, 'base64') : Buffer.alloc(16);
  const expectedHash = user ? Buffer.from(user.passwordHash, 'base64') : Buffer.alloc(64);
  const actualHash = await scrypt(credentials.password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  if (!user || !timingSafeEqual(actualHash, expectedHash)) {
    sendJson(response, 401, { error: 'Email or password is incorrect.' });
    return;
  }
  issueSession(response, user);
}

async function handleMockPayment(request, response) {
  if (!checkSameOrigin(request, response)) return;
  const contentType = request.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    sendJson(response, 415, { error: 'Content-Type must be application/json.' });
    return;
  }

  const input = await readJson(request);
  if (!input || typeof input !== 'object' || Array.isArray(input) || !Array.isArray(input.items)) {
    sendJson(response, 400, { error: 'Please provide the items in your cart.' });
    return;
  }
  if (!input.items.length || input.items.length > PRODUCT_CATALOG.length) {
    sendJson(response, 400, { error: 'Your cart is empty or contains too many items.' });
    return;
  }
  if (!['mock-upi', 'mock-card'].includes(input.paymentMethod)) {
    sendJson(response, 400, { error: 'Choose one of the available demo payment methods.' });
    return;
  }

  const seenIds = new Set();
  const orderItems = [];
  for (const entry of input.items) {
    if (!entry || typeof entry !== 'object' || !Number.isInteger(entry.id) || !Number.isInteger(entry.quantity)) {
      sendJson(response, 400, { error: 'A cart item is invalid.' });
      return;
    }
    const product = PRODUCT_CATALOG.find(item => item.id === entry.id);
    if (!product || seenIds.has(entry.id) || entry.quantity < 1 || entry.quantity > 1000) {
      sendJson(response, 400, { error: 'A cart item is invalid.' });
      return;
    }
    seenIds.add(entry.id);
    const unitPricePaise = Math.round(product.priceInr * 100);
    orderItems.push({
      id: product.id,
      name: product.name,
      unit: product.unit,
      quantity: entry.quantity,
      unitPricePaise,
      lineTotalPaise: unitPricePaise * entry.quantity,
    });
  }

  const totalPaise = orderItems.reduce((sum, item) => sum + item.lineTotalPaise, 0);
  const active = getSession(request);
  const user = active && users.get(active.session.email);
  const order = {
    orderId: `FM-DEMO-${randomBytes(5).toString('hex').toUpperCase()}`,
    status: 'mock-paid',
    createdAt: new Date().toISOString(),
    paymentMethod: input.paymentMethod,
    customerEmail: user ? user.email : null,
    items: orderItems,
    totalPaise,
  };
  fs.appendFileSync(ORDERS_FILE, `${JSON.stringify(order)}\n`, { encoding: 'utf8', mode: 0o600 });
  sendJson(response, 201, {
    orderId: order.orderId,
    status: order.status,
    totalPaise: order.totalPaise,
  });
}

async function handleRequest(request, response) {
  const requestPath = new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`).pathname;
  if (request.method === 'GET' && (requestPath === '/' || requestPath === '/Raw%20Material%20Market%20Place.html')) {
    if (!fs.existsSync(HTML_FILE)) {
      sendJson(response, 404, { error: 'Marketplace HTML file was not found.' });
      return;
    }
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    });
    response.end(fs.readFileSync(HTML_FILE));
    return;
  }

  if (request.method === 'GET' && requestPath === '/api/me') {
    const active = getSession(request);
    const user = active && users.get(active.session.email);
    if (!user) {
      sendJson(response, 200, { user: null });
      return;
    }
    sendJson(response, 200, { user: publicUser(user) });
    return;
  }

  if (request.method === 'POST' && (requestPath === '/api/signup' || requestPath === '/api/login')) {
    await handleAuth(request, response, requestPath);
    return;
  }

  if (request.method === 'POST' && requestPath === '/api/mock-payment') {
    await handleMockPayment(request, response);
    return;
  }

  if (request.method === 'POST' && requestPath === '/api/logout') {
    if (!checkSameOrigin(request, response)) return;
    const active = getSession(request);
    if (active) sessions.delete(active.token);
    clearSessionCookie(response);
    sendJson(response, 200, { user: null });
    return;
  }

  sendJson(response, 404, { error: 'Not found.' });
}

loadUsers();
const server = http.createServer((request, response) => {
  handleRequest(request, response).catch(error => {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    const status = error.status || 500;
    if (status === 500) console.error('Request failed:', error);
    sendJson(response, status, {
      error: status === 500 ? 'The server could not complete the request.' : error.message,
    });
  });
});

server.listen(PORT, HOST, () => {
  const address = `http://${HOST}:${PORT}`;
  console.log(`ForgeMarket is running at ${address}`);
  console.log('Account data is stored locally in backend/data/users.jsonl.');
  if (process.env.OPEN_BROWSER !== '0') {
    execFile('cmd.exe', ['/c', 'start', '', address], error => {
      if (error) console.log(`Open ${address} in your browser to use ForgeMarket.`);
    });
  }
});

server.on('error', error => {
  console.error(`Could not start ForgeMarket on ${HOST}:${PORT}: ${error.message}`);
  if (error.code === 'EADDRINUSE') {
    console.error('The port is already in use. Close the other server window or set PORT to another port.');
  }
  process.exitCode = 1;
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
  for (const [address, attempts] of authAttempts) {
    if (attempts.resetAt <= now) authAttempts.delete(address);
  }
}, 60 * 60 * 1000).unref();
