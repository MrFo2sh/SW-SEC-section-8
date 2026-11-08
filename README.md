# Week — Broken Authentication Lab (DeadDrop) · Part 1

> ⚠️ **Warning**
> This app is **intentionally vulnerable** for teaching purposes only.
> Run it on `localhost` only. Never deploy it to a public server.

DeadDrop is a small "secure notes" web app. It looks clean and professional —
and its authentication is quietly broken in several ways. Your job this week is
to find and exploit those weaknesses, then run the fixed version and prove the
same attacks no longer work.

This is **Part 1 of 2**. Part 1 is **Broken Authentication** (OWASP A07). Next
week, Part 2 reuses this same app for **Broken Access Control** (OWASP A01).

---

## 0) Running the lab

Requirements: Node.js 18+ (tested on 23).

```bash
npm install
npm start          # VULNERABLE mode -> http://localhost:3000
```

To run the fixed (secure) version later:

```bash
# Windows PowerShell
$env:SECURE=1; node server.js

# Linux / macOS
SECURE=1 node server.js
```

The data is rebuilt in memory every time the server starts, so if you break
something, just stop and start again to reset. A banner at the top of every page
tells you which mode you're in.

You get one account to start with — the open-day demo account:

```
username: student
password: student123
```

…or register your own.

---

## 1) What you're attacking

| Area | Endpoint | Question to answer |
|---|---|---|
| Registration | `POST /register` | Does the site tell you which usernames already exist? |
| Login | `POST /login` | What stops someone trying thousands of passwords? |
| Sessions | the `sid` cookie | Look at your session cookie. Is it *really* random? |
| Admin | `GET /admin` | What exactly proves you're an administrator to the server? |

There are **two flags** to capture in Part 1. Each is handed to you by the
server *only* once you've actually carried out the attack — a flag is proof you
succeeded, never a hint.

---

## 2) Tools

- A browser with **DevTools** (Application → Cookies is your friend).
- `curl` for scripted requests.
- A fuzzer such as **ffuf**, and the two wordlists shipped with this lab:
  - `usernames.txt` — ~100 candidate usernames
  - `passwords.txt` — ~100 common passwords

Install ffuf (any one):

```bash
go install github.com/ffuf/ffuf/v2@latest      # with Go
# or download a release binary from github.com/ffuf/ffuf
# on Kali: apt install ffuf
```

---

## 3) Objectives

1. **Enumerate** valid usernames. The registration form behaves differently for
   a name that already exists — use that to find real accounts.
2. **Get a foothold.** One of those accounts (`bob`) has a weak password and the
   login has no brute-force protection. Crack it and sign in.
3. **Inspect your session.** Once you're logged in, look closely at your `sid`
   cookie. It looks random. Is it? Figure out how it's generated.
4. **Find the administrator.** Your enumeration results from step 1 include the
   admin's account — the username is a bit of a giveaway. Then use what you
   learned in step 3 to become them.
5. **Reach `/admin`** and capture the second flag.

### Stretch exercises

6. **Blast radius.** Using your enumerated usernames and `passwords.txt`, crack
   *every* other member's password, not just bob's. One weak account + a
   guessable session scheme = the whole user base falls. Write down how many you
   cracked and how long it took.
7. **Prove the fix.** Run the app in `SECURE=1` mode and repeat objectives 1–5.
   For each one, write one sentence: what change blocked the attack, and why.

---

## 4) What to hand in

- The two flags.
- For each objective (1–5): one or two sentences on *how* you did it.
- Exercise 7: the before/after for each vulnerability (what broke it, what fixed
  it).

Good hunting. Remember: the app looking polished tells you nothing about whether
it's secure.
