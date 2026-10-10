# STUDY MODE + English Buddy

A runnable starter project for a responsive school study planner and English vocabulary trainer.

## Features
- Account creation and login handled by the server (bcrypt password hashing, HTTP-only session cookie).
- SQLite persistence for users, tasks, and vocabulary.
- Study dashboard with task management, focus timer, XP and levels.
- Upload a photo of English vocabulary and extract text in the browser with Tesseract.js; review the extracted lines before saving.
- Responsive black / electric-cyan gaming UI.
- Basic security headers, login rate limiting, parameterized SQL queries, and session configuration.

## Requirements
- Node.js 18+
- Internet connection for loading Tesseract.js from its CDN during photo OCR. The rest of the app runs locally once dependencies are installed.
- A production deployment should use HTTPS and a strong SESSION_SECRET.

## Run
1. Copy `.env.example` to `.env` and set `SESSION_SECRET` to a long random value.
2. Run `npm install`
3. Run `npm start`
4. Open http://localhost:3000

## Important security notes
This is a solid MVP starter, not a claim of "unhackable" security. Before exposing it to the public internet, add email verification and password reset, CSRF protection for all state-changing requests, backups, dependency updates, monitoring, and a proper HTTPS reverse proxy. Set `NODE_ENV=production` behind HTTPS. Never commit `.env` or the SQLite database. Browser-side OCR sends the image to the user's own browser, not this server; Tesseract's library files are loaded from its CDN.

## Data
The server stores user accounts, tasks, and vocabulary in `data/study-mode.sqlite`. Back up that file securely. Each account only receives its own records.
