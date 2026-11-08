// db.js  -----------------------------------------------------------
// In-memory data store for the Broken Authentication lab (OWASP A07).
// Re-seeded on every server start, so students can break things freely
// and just restart to reset.
//
// There is NO SQL and NO planted hints here on purpose: the app must read
// like an ordinary, boring notes app. The only thing that ever reveals a
// successful attack is a flag, and a flag is handed over ONLY as proof the
// student already pulled the exploit off — never as a breadcrumb.
// -------------------------------------------------------------------

const crypto = require('crypto');

const md5 = (s) => crypto.createHash('md5').update(String(s)).digest('hex');
const secureToken = (bytes = 24) => crypto.randomBytes(bytes).toString('hex');

// Fixed, non-randomised flags so every student's answer sheet matches the
// solution.md table exactly. Part 1 (authentication) has two.
const FLAGS = {
  // handed over on bob's dashboard once you are logged in as bob — there is
  // no legitimate path into bob's account, so holding it proves a crack.
  bruteforce: 'FLAG{auth_bruteforce_no_rate_limit}',
  // handed over at /admin when the session resolves to an admin — admin's
  // password is uncrackable, so the only way here is forging the md5 session.
  forged_session: 'FLAG{auth_forged_session_md5_username}',
};

function buildStore() {
  // Passwords are plaintext ONLY because this is a teaching lab demonstrating
  // insecure practice. NEVER store passwords like this in real code.
  //
  //  - admin (dd_root_07) has a strong password that is NOT on any wordlist,
  //    so it can never be guessed; the only way to an admin session is forging
  //    sid = md5("dd_root_07").
  //  - every other account has a weak password that IS on passwords.txt, so
  //    bob (the first foothold) and the rest are all crackable.
  const users = [
    // id, username,     password,          displayName,     role,      email
    mkUser(1, 'dd_root_07', 'Zx9#Qv!m2_Lp7',  'Site Admin',    'admin',   'root@deaddrop.local'),
    mkUser(2, 'alice',      'sunshine',        'Alice Nguyen',  'user',    'alice@deaddrop.local'),
    mkUser(3, 'bob',        'qwerty',          'Bob Reyes',     'user',    'bob@deaddrop.local'),
    mkUser(4, 'charlie',    'password1',       'Charlie Dunn',  'user',    'charlie@deaddrop.local'),
    mkUser(5, 'dave',       'letmein',         'Dave Osei',     'user',    'dave@deaddrop.local'),
    mkUser(6, 'support',    'monkey',          'Support Desk',  'support', 'support@deaddrop.local'),
    mkUser(7, 'student',    'student123',      'Open Day Demo', 'user',    'student@deaddrop.local'),
  ];

  // Mundane notes. Nothing secret, nothing that hints at any vulnerability.
  const notes = [
    mkNote(1, 2, 'Groceries',      'oat milk, tomatoes, coffee, dish soap'),
    mkNote(2, 2, 'Standup',        'done: invoices. today: follow up with vendor. blockers: none'),
    mkNote(3, 3, 'Gym',            'mon/wed/fri — leg day is wednesday, do not skip again'),
    mkNote(4, 3, 'Books',          'finish the Le Guin, start the project-management one'),
    mkNote(5, 4, 'Trip',          'passport expires may — renew before booking flights'),
    mkNote(6, 5, 'Recipes',        'the lentil soup needs more cumin next time'),
    mkNote(7, 6, 'Shift notes',    'quiet week on tickets, mostly password resets'),
    mkNote(8, 7, 'Welcome',        'open-day demo account — poke around, nothing important here'),
  ];

  const store = {
    users,
    notes,
    nextUserId: users.length + 1,
    nextNoteId: notes.length + 1,
    sessions: new Map(),      // SECURE mode: random token -> userId
    loginFails: new Map(),    // SECURE mode: username -> { count, until }
    registerHits: new Map(),  // SECURE mode: ip -> { count, until } (rate limit)
    FLAGS,
  };
  return store;
}

function mkUser(id, username, password, displayName, role, email) {
  return { id, username, password, displayName, role, email };
}
function mkNote(id, ownerId, title, body) {
  return { id, ownerId, title, body };
}

module.exports = { buildStore, FLAGS, md5, secureToken };
