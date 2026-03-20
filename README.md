# CyberMentor 🛡️
**AI-powered SOC & Cloud Security Mentor**

## ⚡ Quick Deploy to Vercel (Free)

### Step 1 — Add your API Key
Open `src/App.jsx` and replace line 7:
```js
const API_KEY = 'YOUR_ANTHROPIC_API_KEY_HERE'
```
With your key from https://console.anthropic.com

### Step 2 — Push to GitHub
1. Go to https://github.com/new and create a new repo called `cybermentor`
2. Run these commands in your terminal:
```bash
cd cybermentor
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cybermentor.git
git push -u origin main
```

### Step 3 — Deploy on Vercel
1. Go to https://vercel.com and sign up (free)
2. Click **"Add New Project"**
3. Import your `cybermentor` GitHub repo
4. Click **Deploy** — that's it!

Your app will be live at: `https://cybermentor-xxx.vercel.app`

---

## 🔒 Secure API Key (Recommended)
Instead of hardcoding the key, use Vercel Environment Variables:
1. In Vercel dashboard → Settings → Environment Variables
2. Add: `VITE_ANTHROPIC_KEY` = your API key
3. In `src/App.jsx` change line 7 to:
```js
const API_KEY = import.meta.env.VITE_ANTHROPIC_KEY
```

---

## 🏃 Run Locally
```bash
npm install
npm run dev
```
Open http://localhost:5173

## 📦 Build
```bash
npm run build
```

---

## Features
- 💬 **Ask Mentor** — Chat with AI about any SOC/Cloud topic
- 🗺️ **Roadmap** — Full 30-day preparation plan
- ⚡ **Practice MCQ** — Infinite AI-generated questions (Easy/Medium/Hard)
- 📚 **Topics** — Click any topic for a structured lesson
- 📊 **Progress** — AI analysis of your performance
