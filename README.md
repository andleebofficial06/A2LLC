# A2LLC Tutors

A fully functional teacher/student tutoring portal: separate sign-up and
sign-in for teachers and students, a real backend, and a database that
persists between visits.

**Zero npm dependencies.** It's built entirely on Node's built-in modules
(`http`, `crypto`, `node:sqlite`), so `node server.js` works with nothing
but Node.js itself — no `npm install` required, no native compilation, no
version conflicts.

## What it does

**Teachers**
- Sign up with name, email, password, and subject
- Set weekly availability (which days, which hours, in EST)
- See booked classes on a calendar and mark each Done / Cancelled / Pending
- Message any student who has booked with them (shown to students under a pseudonym)

**Students**
- Sign up with name, email, password (get an auto-generated student code)
- Browse/search tutors by subject
- Book any open hour from a tutor's next two weeks of availability
- See all booked classes and their status
- Message tutors they've booked with

Data is real and persists: it's stored in a SQLite database file
(`a2llc.db`) that's created automatically the first time you run the server.

## Run it locally

Requires **Node.js 20 or newer** (uses the built-in `node:sqlite` module).

```bash
node server.js
```

Then open **http://localhost:3000** in your browser.

That's it — no build step, no install step. The first run creates
`a2llc.db` automatically.

To use a different port:
```bash
PORT=8080 node server.js
```

## Deploying so it's live on the internet

Since this has no dependencies, deployment is simple. Any host that runs
Node.js will work — for example [Render](https://render.com),
[Railway](https://railway.app), or [Fly.io](https://fly.io):

1. Push this folder to a GitHub repo (or upload it directly if the host allows).
2. Create a new "Web Service" from the repo.
3. Build command: *(leave blank / not needed)*
4. Start command: `node server.js`
5. Set an environment variable `JWT_SECRET` to a long random string (important for real use — see below).

**One important note on hosting:** SQLite is a single file on disk. Most
free-tier hosts wipe the filesystem on every redeploy, which means your
`a2llc.db` (all accounts, classes, messages) would reset. For anything
beyond a demo, either:
- use a host with a **persistent disk/volume** (Render and Fly.io both offer this), or
- swap `db.js` for a hosted database later (Postgres, Turso, etc.) — the
  rest of the app (server.js, index.html) doesn't need to change, only the
  handful of functions in `db.js`.

## Security notes before real use

- Set `JWT_SECRET` to a long random value in production (don't use the default).
- Passwords are hashed with scrypt (Node's built-in `crypto.scryptSync`) — never stored in plain text.
- This demo doesn't send real emails (no password reset, no verification) — add that before onboarding real users.
- Consider adding rate limiting on `/api/auth/login` if this goes public.

## Project structure

```
a2llc-tutors/
├── server.js       # HTTP server + all API routes (no dependencies)
├── db.js           # SQLite schema + query helpers (node:sqlite)
├── package.json
├── public/
│   └── index.html  # entire frontend: home page, teacher & student auth, both dashboards
└── a2llc.db        # created automatically on first run
```

## Test account you can create

There's no seeded demo account — sign up fresh from the home page as
either a teacher or a student. Everything (including the calendar,
availability, and messaging) is live and wired to the database from the
first signup.
