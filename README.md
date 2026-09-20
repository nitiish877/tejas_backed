# Tejas AI - Backend (Railway Deploy)

This is the standalone backend service for **Tejas AI**, handling AI model streaming via Hugging Face and version checking.

## 🚀 How to Deploy on Railway.app

1. **Create a GitHub Repo** for this backend:
   - Upload the files inside this `backend/` folder (`server.ts`, `package.json`, `tsconfig.json`, `.env.example`).
2. **Go to [Railway.app](https://railway.com)** and log in.
3. Click **"+ New Project"** -> **"Deploy from GitHub repo"** -> Select your backend repo.
4. **Add Environment Variables** in Railway Dashboard ("Variables" tab):
   - `HF_TOKEN`: Your Hugging Face token (`hf_...`)
   - `NODE_ENV`: `production`
5. **Get Your Backend URL:**
   - In Railway, go to **Settings** -> **Networking** -> click **"Generate Domain"**.
   - Copy your live URL (e.g. `https://tejas-ai-backend.up.railway.app`).
   - Use this URL as `VITE_BACKEND_URL` in your frontend!
