// server.js  ---------------------------------------------------------
// DeadDrop — Broken Authentication lab (OWASP A07).  LOCALHOST ONLY.
//
//   node server.js            -> VULNERABLE mode  (default)
//   SECURE=1 node server.js   -> FIXED mode
//   (Windows PowerShell:  $env:SECURE=1; node server.js )
//
// Every vulnerability below is exploitable in VULNERABLE mode and blocked
// in SECURE mode. The two differ ONLY in the clearly-marked branches, so
// students can diff the behaviour, not a rewrite.
// --------------------------------------------------------------------

const express = require('express');
const cookieParser = require('cookie-parser');
const { buildStore, md5, secureToken } = require('./db');

const SECURE = process.env.SECURE === '1';
const PORT = process.env.PORT || 3000;

const app = express();
const store = buildStore();

app.use(cookieParser());
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

// --- tiny helpers ----------------------------------------------------
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function findUser(username) {
  return store.users.find((u) => u.username === username);
}

// Resolve the user a request is "logged in" as, from the `sid` cookie.
//
//  VULNERABLE: the session id IS md5(username). We find whichever user's
//  username hashes to the cookie — so anyone who knows (or guesses) a
//  username can forge that user's session. No server-side session needed.
//
//  SECURE: the sid is an unguessable random token minted at login and stored
//  server-side. Forging md5(username) resolves to nobody.
function currentUser(req) {
  const sid = req.cookies.sid;
  if (!sid) return null;
  if (SECURE) {
    const uid = store.sessions.get(sid);
    return store.users.find((u) => u.id === uid) || null;
  }
  return store.users.find((u) => md5(u.username) === sid) || null;
}

function startSession(res, user) {
  if (SECURE) {
    const token = secureToken();
    store.sessions.set(token, user.id);
    res.cookie('sid', token, { httpOnly: true, sameSite: 'lax' });
  } else {
    // VULNERABLE: predictable, forgeable session identifier.
    res.cookie('sid', md5(user.username), { sameSite: 'lax' });
  }
}

// --- shared layout ---------------------------------------------------
function layout(title, body, me) {
  const adminLink = me && me.role === 'admin'
    ? `<a href="/members" class="px-2.5 py-1.5 rounded-md hover:bg-slate-100">Members</a>`
    : '';
  const nav = me
    ? `<span class="text-slate-500 text-sm">${esc(me.displayName)}</span>
       <a href="/dashboard" class="px-2.5 py-1.5 rounded-md hover:bg-slate-100">Dashboard</a>
       ${adminLink}
       <a href="/logout" class="text-indigo-600 hover:underline">Sign out</a>`
    : `<a href="/login" class="text-indigo-600 hover:underline">Sign in</a>
       <a href="/register" class="rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-4 py-1.5">Register</a>`;
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · DeadDrop</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  body{font-family:'Space Grotesk',system-ui,sans-serif;background:#f3f5fa;color:#0f172a;}
  code,kbd,.mono{font-family:'JetBrains Mono',ui-monospace,monospace;}
  .card{box-shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px -12px rgba(16,24,40,.18);}
</style></head>
<body class="min-h-screen antialiased text-[15px]">
<div class="bg-amber-50 border-b border-amber-200 text-amber-700 text-[11px] text-center py-1 mono">lab environment · localhost only · ${SECURE ? 'SECURE mode' : 'VULNERABLE mode'}</div>
<header class="sticky top-0 z-30 bg-white/90 backdrop-blur border-b border-slate-200">
  <div class="max-w-4xl mx-auto px-4 h-14 flex items-center gap-3">
    <a href="/" class="flex items-center gap-2 font-bold">
      <span class="grid place-items-center w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-emerald-500 text-white">◈</span>
      Dead<span class="-ml-2 text-indigo-600">Drop</span></a>
    <nav class="ml-auto flex items-center gap-1 text-sm text-slate-600">${nav}</nav>
  </div>
</header>
<main class="max-w-2xl mx-auto px-4 py-10">${body}</main>
<footer class="max-w-4xl mx-auto px-4 py-8 text-xs text-slate-400 border-t border-slate-200 mt-8">
  <span class="mono">DeadDrop</span> · Lighthouse Collective · <span class="mono">hello@deaddrop.local</span></footer>
</body></html>`;
}

const flagBanner = (flag) => `
<div class="mt-5 rounded-xl border border-emerald-300 bg-emerald-50 p-4">
  <div class="text-emerald-700 font-semibold text-sm">Nice — challenge solved.</div>
  <div class="mono text-emerald-800 mt-1 text-lg break-all">${esc(flag)}</div>
</div>`;

const notice = (msg, ok) => !msg ? '' : `
<div class="mb-4 rounded-lg border ${ok ? 'border-emerald-300 bg-emerald-50 text-emerald-800' : 'border-rose-300 bg-rose-50 text-rose-800'} px-4 py-2.5 text-sm">${esc(msg)}</div>`;

// Send a full HTML page with an explicit status code. Every auth response below
// renders inline (no 302 redirects), so the HTTP status *is* the signal: a
// fuzzer can match on it directly (ffuf -mc / -fc) instead of parsing bodies.
//
//   200 ok · 201 created · 400 bad input · 401 unauthenticated/bad creds
//   403 forbidden (wrong role) · 409 username taken · 429 rate-limited/locked
const page = (res, status, title, body, me) => res.status(status).send(layout(title, body, me));

function dashboardBody(me) {
  const myNotes = store.notes.filter((n) => n.ownerId === me.id);
  const notesHtml = myNotes.length
    ? myNotes.map((n) => `<li class="rounded-lg border border-slate-200 bg-white p-4">
        <div class="font-semibold">${esc(n.title)}</div>
        <div class="text-slate-500 text-sm mt-1">${esc(n.body)}</div></li>`).join('')
    : `<li class="text-slate-400 text-sm">No notes yet.</li>`;
  // Proof-of-success: there is no legitimate route into bob's account, so
  // seeing this page as bob means his password was cracked.
  const flag = me.username === 'bob' ? flagBanner(store.FLAGS.bruteforce) : '';
  return `
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold">Your notes</h1>
    <span class="text-xs mono text-slate-400">signed in as ${esc(me.username)} · ${esc(me.role)}</span>
  </div>
  <ul class="mt-5 space-y-3">${notesHtml}</ul>
  ${flag}`;
}

// --- routes ----------------------------------------------------------
app.get('/', (req, res) => {
  const me = currentUser(req);
  res.send(layout('Home', `
  <section class="rounded-xl border border-slate-200 bg-white p-7 card">
    <h1 class="text-2xl font-bold">Secure notes, with a human on support.</h1>
    <p class="mt-2 text-slate-500">Create an account, keep your notes, open a ticket if anything breaks.</p>
    <div class="mt-6 flex gap-3">
      <a href="/register" class="rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5">Create account</a>
      <a href="/login" class="rounded-lg border border-slate-300 hover:border-indigo-400 px-5 py-2.5">Sign in</a>
    </div>
  </section>`, me));
});

// --- registration (username enumeration lives here) ------------------
app.get('/register', (req, res) => {
  res.send(layout('Register', form('register', req.query.msg, req.query.ok === '1'), currentUser(req)));
});

app.post('/register', (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  const ip = req.ip;

  if (SECURE) {
    // Rate-limit registration attempts per IP to blunt enumeration/abuse.
    const now = Date.now();
    const rec = store.registerHits.get(ip) || { count: 0, until: 0 };
    if (now < rec.until) {
      return page(res, 429, 'Register', form('register', 'Too many attempts. Try again shortly.'), null);
    }
    rec.count += 1;
    if (rec.count >= 10) { rec.until = now + 60000; rec.count = 0; }
    store.registerHits.set(ip, rec);

    // Do NOT confirm whether the username exists: identical 200 response
    // whether taken or available, and no auto-login, so there is no oracle.
    if (!username || !password) {
      return page(res, 400, 'Register', form('register', 'Username and password are required.'), null);
    }
    if (!findUser(username)) {
      store.users.push({
        id: store.nextUserId++, username, password,
        displayName: username, role: 'user', email: username + '@deaddrop.local',
      });
    }
    return page(res, 200, 'Register',
      form('register', 'If that username is available, your account has been created. Try signing in.', true), null);
  }

  // VULNERABLE mode -----------------------------------------------------
  if (!username || !password) {
    return page(res, 400, 'Register', form('register', 'Username and password are required.'), null);
  }
  if (findUser(username)) {
    // Leaks that the username is taken -> enumeration primitive.
    // 409 Conflict is the signal a fuzzer matches on (ffuf -mc 409).
    return page(res, 409, 'Register', form('register', 'That username is already taken.'), null);
  }
  const user = {
    id: store.nextUserId++, username, password,
    displayName: username, role: 'user', email: username + '@deaddrop.local',
  };
  store.users.push(user);
  startSession(res, user);
  return page(res, 201, 'Dashboard', dashboardBody(user), user);
});

// --- login (no rate limit = brute force) -----------------------------
app.get('/login', (req, res) => {
  res.send(layout('Sign in', form('login', req.query.msg, false), currentUser(req)));
});

app.post('/login', (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  if (SECURE) {
    // Account lockout after repeated failures.
    const now = Date.now();
    const rec = store.loginFails.get(username) || { count: 0, until: 0 };
    if (now < rec.until) {
      // 429 = locked: the fuzzer is throttled, so brute-force stalls.
      return page(res, 429, 'Sign in', form('login', 'Account temporarily locked. Try again later.'), null);
    }
    const user = findUser(username);
    if (!user || user.password !== password) {
      rec.count += 1;
      if (rec.count >= 5) { rec.until = now + 60000; rec.count = 0; }
      store.loginFails.set(username, rec);
      return page(res, 401, 'Sign in', form('login', 'Invalid credentials.'), null);
    }
    store.loginFails.delete(username);
    startSession(res, user);
    return page(res, 200, 'Dashboard', dashboardBody(user), user);
  }

  // VULNERABLE: unlimited attempts, no delay, no lockout -> brute-forceable.
  // (Login error stays generic on purpose; enumeration is via /register.)
  // 401 on failure, 200 on success -> ffuf -mc 200 (or -fc 401) finds the password.
  const user = findUser(username);
  if (!user || user.password !== password) {
    return page(res, 401, 'Sign in', form('login', 'Invalid credentials.'), null);
  }
  startSession(res, user);
  return page(res, 200, 'Dashboard', dashboardBody(user), user);
});

app.get('/logout', (req, res) => {
  if (SECURE && req.cookies.sid) store.sessions.delete(req.cookies.sid);
  res.clearCookie('sid');
  res.send(layout('Signed out', `
  <section class="rounded-xl border border-slate-200 bg-white p-7 card text-center">
    <h1 class="text-xl font-bold">You're signed out.</h1>
    <a href="/login" class="inline-block mt-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5">Sign in again</a>
  </section>`, null));
});

// --- dashboard (bob's carries the brute-force flag) ------------------
app.get('/dashboard', (req, res) => {
  const me = currentUser(req);
  if (!me) return page(res, 401, 'Sign in', form('login', 'Please sign in.'), null);
  return page(res, 200, 'Dashboard', dashboardBody(me), me);
});

// --- members directory (ADMIN-ONLY — correct access control) ---------
// This is a legitimate admin feature, gated in BOTH modes. Access control is
// Part 2's subject (Broken Access Control / A01); Part 1 keeps this correct so
// the authentication lessons stand on their own. The admin's username is found
// the authentication way instead — via /register enumeration.
app.get('/members', (req, res) => {
  const me = currentUser(req);
  if (!me) return page(res, 401, 'Sign in', form('login', 'Please sign in.'), null);
  if (me.role !== 'admin') {
    return page(res, 403, 'Members',
      `<div class="rounded-xl border border-rose-200 bg-rose-50 p-6 text-rose-800">403 — the member directory is restricted to administrators.</div>`, me);
  }

  const rows = store.users.map((u) => `
    <tr class="border-t border-slate-100">
      <td class="py-2 pr-4 mono">${esc(u.username)}</td>
      <td class="py-2 pr-4">${esc(u.displayName)}</td>
      <td class="py-2"><span class="text-xs rounded-full px-2 py-0.5 ${u.role === 'admin' ? 'bg-indigo-100 text-indigo-700' : 'bg-slate-100 text-slate-600'}">${esc(u.role)}</span></td>
    </tr>`).join('');
  res.send(layout('Members', `
  <h1 class="text-2xl font-bold">Member directory</h1>
  <p class="text-slate-500 text-sm mt-1">Everyone at DeadDrop.</p>
  <table class="mt-5 w-full text-sm bg-white rounded-xl border border-slate-200 overflow-hidden card">
    <thead class="bg-slate-50 text-slate-500 text-left"><tr>
      <th class="py-2 px-4 font-medium">Username</th><th class="py-2 px-4 font-medium">Name</th><th class="py-2 px-4 font-medium">Role</th>
    </tr></thead><tbody>${rows}</tbody></table>`, me));
});

// --- admin (forged-session flag) -------------------------------------
app.get('/admin', (req, res) => {
  const me = currentUser(req);
  if (!me) return page(res, 401, 'Sign in', form('login', 'Please sign in.'), null);
  if (me.role !== 'admin') {
    return page(res, 403, 'Admin',
      `<div class="rounded-xl border border-rose-200 bg-rose-50 p-6 text-rose-800">403 — administrators only.</div>`, me);
  }
  res.send(layout('Admin', `
  <h1 class="text-2xl font-bold">Admin console</h1>
  <p class="text-slate-500 text-sm mt-1">Signed in as <span class="mono">${esc(me.username)}</span>.</p>
  <div class="mt-5 grid grid-cols-3 gap-3 text-center">
    <div class="rounded-xl border border-slate-200 bg-white p-4"><div class="text-2xl font-bold">${store.users.length}</div><div class="text-xs text-slate-500">users</div></div>
    <div class="rounded-xl border border-slate-200 bg-white p-4"><div class="text-2xl font-bold">${store.notes.length}</div><div class="text-xs text-slate-500">notes</div></div>
    <div class="rounded-xl border border-slate-200 bg-white p-4"><div class="text-2xl font-bold">1</div><div class="text-xs text-slate-500">region</div></div>
  </div>
  ${flagBanner(store.FLAGS.forged_session)}`, me));
});

// --- shared auth form ------------------------------------------------
function form(kind, msg, ok) {
  const isReg = kind === 'register';
  return `
  <section class="rounded-xl border border-slate-200 bg-white p-7 card max-w-md mx-auto">
    <h1 class="text-xl font-bold">${isReg ? 'Create your account' : 'Sign in'}</h1>
    ${notice(msg, ok)}
    <form method="post" action="/${kind}" class="mt-4 space-y-3">
      <label class="block">
        <span class="text-sm text-slate-600">Username</span>
        <input name="username" autocomplete="off" class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 focus:border-indigo-400 focus:outline-none" required>
      </label>
      <label class="block">
        <span class="text-sm text-slate-600">Password</span>
        <input name="password" type="password" autocomplete="off" class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 focus:border-indigo-400 focus:outline-none" required>
      </label>
      <button class="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-4 py-2.5">${isReg ? 'Register' : 'Sign in'}</button>
    </form>
    <p class="mt-4 text-sm text-slate-500">${isReg
      ? 'Already have an account? <a class="text-indigo-600 hover:underline" href="/login">Sign in</a>'
      : 'New here? <a class="text-indigo-600 hover:underline" href="/register">Create an account</a>'}</p>
  </section>`;
}

app.listen(PORT, () => {
  console.log(`DeadDrop auth lab on http://localhost:${PORT}  [${SECURE ? 'SECURE' : 'VULNERABLE'} mode]`);
});
