# Xsquad GitHub V2 — Render Preview

A substantial preview build intended for testing on Render. The frontend is one `client/index.html` file containing HTML, CSS, and browser JavaScript. The backend is Node.js + Express; PostgreSQL is used for persistent data; Google Gemini is an optional AI assistant.

## Included
- Responsive Xsquad GitHub-style interface
- Single-file frontend (HTML/CSS/JS combined)
- Express API and Render deployment blueprint
- PostgreSQL schema auto-initialized on startup
- Register/login with bcrypt and JWT
- User profile read/update
- Create/list repositories; public/private access checks
- Create/read/delete files and folders
- Upload text-based files from browser
- Application-level file version history and commit log
- Raw file endpoint: `/raw/:owner/:repo/:branch/:path`
- Issues create/list/close; repository stars
- Google Gemini assistant via server-side API key
- Rate limiting, Helmet, compression, parameterized SQL, path traversal checks
- Basic validation tests

## Deploy to Render
1. Push the extracted project to a Git repository.
2. Render → New → Blueprint (or Web Service).
3. Select repository; use `server` as Root Directory.
4. Build command: `npm install`; Start command: `npm start`.
5. Create a PostgreSQL database on Render. Set `DATABASE_URL` to its **Internal Database URL**.
6. Set environment variables:
   - `NODE_ENV=production`
   - `DATABASE_URL` = Render PostgreSQL Internal Database URL
   - `JWT_SECRET` = random secret at least 32 characters
   - `CLIENT_ORIGIN` = deployed site URL (optional if same-origin)
   - `GOOGLE_API_KEY` = Google AI Studio API key (optional)
   - `GEMINI_MODEL=gemini-2.5-flash`
7. Deploy. Open `/api/health`. It should report `ok:true` and `database:"connected"`.

The included `server/render.yaml` can create the web service and database through Render Blueprint. Review its settings before deployment. Never commit `.env`.

## Local run
`cd server && cp .env.example .env && npm install && npm run dev`
Open `http://localhost:10000`.

## Google AI
Create an API key in Google AI Studio and add it as `GOOGLE_API_KEY` in Render Environment. The key stays on the server and is never sent to the browser. Sign in to use `/api/ai/chat`. AI responses are suggestions; the assistant does not autonomously commit code.

## Preview status / honest limitations
This is a **Preview / Beta foundation**, not a fully equivalent GitHub replacement. Features included above are implemented at application level, but this build does not include native Git smart HTTP/SSH, true Git object storage, branches/merge engine, pull-request diffs/reviews, CI runners, package registry, OAuth/email verification/password reset, organizations/teams, malware scanning, quota enforcement, backups, or production-grade observability. Upload currently reads browser files as text; binary asset storage requires object storage integration. Run tests and verify deployment before public use.

## Tests
From `server`: `npm test` and `npm run check`.
