# 🏆 MLH x ROUNDTABLE · Participant Guide
## From Setup to Submission

Everything your team needs to get started, build, and hand in your project using the official hackathon starter made by `create-roundtable-mlh-boilerplate`.

---

## ⚡ Quick Start

### 1. Scaffold your team project

Run the generator in your terminal:

```bash
npx create-roundtable-mlh-boilerplate
```
*(or `npm create roundtable-mlh-boilerplate`)*

*(No project name needed in the command — the CLI wizard will ask for your project name!)*

### 2. Answer the setup questions

The CLI asks a handful of quick questions. Here is what each one wants:

| Prompt | What to enter |
| :--- | :--- |
| **Project name** | Lowercase, kebab-case (e.g. `smart-health`) |
| **Team name** | Your registered team name (e.g. `Code Ninjas`) |
| **One-line tagline** | A one-sentence pitch, 80 characters max |
| **Team members** | Names separated by commas (e.g. `Aryan, Priya, Dev`) |
| **Problem statement** | The core problem your project solves, 300 characters max |
| **Frontend framework** | `Next.js 14`, `React (Vite)`, or `Vanilla HTML/JS` |
| **Backend framework** | `Express`, `Fastify`, or `None (frontend only)` |
| **Database** | `MongoDB`, `PostgreSQL`, `SQLite`, or `None` |
| **Authentication** | `JWT`, `Session-based`, or `None` |
| **Add-ons** | Press space to pick: `Docker setup`, `TailwindCSS`, `Socket.io` |
| **Install dependencies now?** | Type `y` and it installs everything for you |

---

## 🛠️ Local Environment Setup

### 1. Go into your project folder

```bash
cd <project-name>
```

### 2. Check the baseline Git commit

Make sure the starter commit was recorded:

```bash
git log -1 --oneline
```

You should see:
```text
<hash> Initial hackathon boilerplate
```

> **Fair play:** Judges look at commit timestamps. That first commit is the clean baseline from the organizers, so every feature you build should land in commits made during the hackathon.

### 3. Set up your environment variables

Copy the example file inside `server/` to create your real one:

```bash
cp server/.env.example server/.env
```

Then open `server/.env` and fill in your secrets and database connection:

```env
PORT=5000
NODE_ENV=development

# If using MongoDB:
DATABASE_URL=mongodb://localhost:27017/<project-name>

# If using PostgreSQL:
DATABASE_URL=postgresql://user:password@localhost:5432/<project-name>

# If using JWT auth:
JWT_SECRET=super-secret-hackathon-key
```

### 4. Start the dev servers

Open two terminal windows (or tabs).

**Terminal 1 · Frontend:**
```bash
npm run dev:client
```
The client opens at `http://localhost:3000` (Next.js) or `http://localhost:5173` (Vite).

**Terminal 2 · Backend:**
```bash
npm run dev:server
```
The API runs at `http://localhost:5000`. Check that it is alive at `http://localhost:5000/api/health`.

---

## 📁 Folder Layout & Conventions

This is where your team should put its code:

```text
<project-name>/
├── client/                     # FRONTEND CODE
│   ├── src/ (or app/)
│   │   ├── components/         # Reusable UI pieces (Navbar, Cards, Modals)
│   │   ├── pages/ (or views/)  # Main views and dashboard routes
│   │   ├── services/ (or api/) # Axios/fetch helpers that call the backend
│   │   └── styles/             # CSS / Tailwind configuration
│   └── package.json
│
├── server/                     # BACKEND CODE
│   ├── src/
│   │   ├── config/db.js        # Database connection and ORM/ODM setup
│   │   ├── controllers/        # Route logic (req, res handlers)
│   │   ├── middleware/         # Auth (JWT check), validation, error handling
│   │   ├── models/             # Database schemas (Mongoose, SQL tables)
│   │   ├── routes/             # API endpoint definitions (/api/...)
│   │   └── index.js            # Express/Fastify entry point
│   ├── .env                    # Secrets (never commit this)
│   └── package.json
│
├── hackathon.config.json       # Team and stack details
└── README.md                   # Project documentation
```

---

## 🚀 Suggested Build Order

There is no fixed schedule. Work through these stages in order, and spend as long on each as your team needs:

| Stage | Focus | What to get done |
| :--- | :--- | :--- |
| **1** | **Planning & contracts** | Pick one core user journey. Define your API endpoints in `server/src/routes/` and your database schemas in `server/src/models/`. |
| **2** | **Core feature (MVP)** | Build the one feature that matters, end to end. Skip settings pages, profile editors and password resets for now. |
| **3** | **Frontend & integration** | Connect the frontend to your backend endpoints and replace any hardcoded mock data with real API calls. |
| **4** | **Seed data & polish** | Add sample data so your demo is never empty. Handle loading spinners and error messages. |

---

## 🔌 API Wiring Cheat Sheet

### Calling your backend from the frontend

Plain `fetch` or `axios` both work in your client:

```javascript
// client/src/services/api.js
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

export async function fetchHealth() {
  const res = await fetch(`${API_URL}/health`);
  return res.json();
}

export async function createItem(data, token) {
  const res = await fetch(`${API_URL}/items`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    },
    body: JSON.stringify(data)
  });
  return res.json();
}
```

### Adding a new backend route

1. **Write the controller in `server/src/controllers/itemController.js`:**
```javascript
export async function getItems(req, res) {
  try {
    // Replace with a real database query
    const items = [{ id: 1, name: 'Sample Item' }];
    res.status(200).json({ success: true, data: items });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
}
```

2. **Register the route in `server/src/routes/apiRoutes.js`:**
```javascript
import { Router } from 'express';
import { getHealth } from '../controllers/healthController.js';
import { getItems } from '../controllers/itemController.js';

const router = Router();

router.get('/health', getHealth);
router.get('/items', getItems);

export default router;
```

---

## 🛡️ Git Habits That Help

1. **Work on feature branches:**
   ```bash
   git checkout -b feature/auth
   git checkout -b feature/dashboard
   ```
2. **Commit early and often:**
   Short messages that say what changed are enough:
   ```bash
   git commit -m "feat(api): add item creation endpoint"
   git commit -m "feat(ui): implement responsive navbar and card grid"
   ```
3. **Never commit secrets:**
   Keep `.env` inside `.gitignore`. Put placeholder values in `.env.example` instead.

---

## 🐙 Pushing to GitHub

Name your repository like this:
```text
<team-name>_<project-name>
```

For example, a team called **Code Ninjas** building **Smart Health** would use:
`code-ninjas_smart-health`.

Make the repository public on GitHub, then connect your local project and push:

```bash
git remote add origin https://github.com/<your-username>/<team-name>_<project-name>.git
git branch -M main
git push -u origin main
```

---

## 🌐 Deploy Your App

You will be asked for a live link, so your project has to be deployed and working on the internet, not just on your laptop. Any hosting service is fine (**Vercel**, **Netlify**, and **Render** are common choices).

### Before you call it done:
1. **Deploy both the frontend and the backend**, and set your environment variables (`DATABASE_URL`, `JWT_SECRET`, and so on) on the host.
2. **Point the frontend at the live backend** by setting `VITE_API_URL` to your deployed API address.
3. **Open the deployed link in a fresh browser window (or incognito)** and go through the whole user flow, from login to your main feature. Fix anything that only worked locally.
4. **Keep the live link handy.** Do not take the deployment down after you submit.

---

## 👤 Test Account

If your app has a login, judges must be able to get in without asking you.

> **Tip:** Put the test account on the login page itself, where anyone opening the app can see it (a small "Demo credentials" box under the form works well). Do not put it only in the README.

- **Email:** `demo@hackathon.com`
- **Password:** `password123`

---

## 📋 Final Submission Checklist

You will be asked for two links when you submit: your **GitHub repository** and your **deployed URL**. Make sure you have all of this:

- [ ] **GitHub link:** A public repository named `<team-name>_<project-name>` that contains all your commits.
- [ ] **Deployed URL:** Your app is live, and you have opened the link yourself and checked that it works.
- [ ] **Working demo:** The app also runs locally without crashing using `npm install`, `npm run dev:client` and `npm run dev:server`.
- [ ] **Test account on the login page:** Demo credentials are visible on the login screen, not just in the README.
- [ ] **Verified commit history:** The baseline commit `"Initial hackathon boilerplate"`, followed by your own development commits.
- [ ] **Completed README.md:** A clear write-up of your problem statement, solution, architecture, and instructions for judges.

---

*Good luck, teams. Build something you are proud of.* 🚀
