import express, { Request, Response } from 'express';
import compression from 'compression';
import dotenv from 'dotenv';
import { initDb, purgeExpiredEphemeralChats, purgeOldChats } from './db';
import authRoutes from './authRoutes';
import './firebaseAdmin';

dotenv.config();

const app = express();
app.set('trust proxy', 1); // Railway proxy ke peeche real IP (rate-limit ke liye)
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const HF_MODEL = 'meta-llama/Llama-3.2-1B-Instruct';
const FALLBACK_MODEL = 'meta-llama/Llama-3.1-8B-Instruct';

// Sanitize token (e.g. if 'h' was trimmed or missing)
function getCleanToken(tokenCandidate?: string): string {
  let token = (
    tokenCandidate ||
    process.env.HF_TOKEN ||
    process.env.HF_ACCESS_TOKEN ||
    process.env.HUGGINGFACE_API_TOKEN ||
    ''
  ).trim();

  // Remove wrapping quotes if any
  if ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"))) {
    token = token.slice(1, -1).trim();
  }
  if (token.startsWith('f_') && token.length > 30) {
    token = 'h' + token;
  }
  return token;
}

// Gzip compression — JSON responses 80% chhoti ho jaati hain
app.use(compression());

// Enable CORS for external access (allow Vercel, localhost, Android WebView)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Guest-Id');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json({ limit: '2mb' }));

// Login / register / chat-sync / payments / shares / OAuth routes
app.use('/api', authRoutes);

// API Version & Changelog (Used by frontend to check updates)
const CURRENT_APP_VERSION = '1.0.1';

app.get('/api/version', (req: Request, res: Response) => {
  res.json({
    version: CURRENT_APP_VERSION,
    releaseDate: '2026-09-18',
    changelog: 'Fast response streaming, model access restrictions, and persistent update system.',
    apkDownloadUrl: '/Tejas.apk'
  });
});

// API Health & Status check
app.get('/api/status', (req: Request, res: Response) => {
  const envToken = getCleanToken();
  res.json({
    status: 'ok',
    primaryModel: HF_MODEL,
    fallbackModel: FALLBACK_MODEL,
    hasTokenInEnv: Boolean(envToken && envToken.startsWith('hf_')),
    instructions: {
      step1: 'Create a Hugging Face account at https://huggingface.co',
      step2: 'Visit https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct and accept license terms',
      step3: 'Generate a User Access Token (Read role) at https://huggingface.co/settings/tokens',
      step4: 'Add HF_TOKEN=hf_your_token_here in Railway Variables or .env'
    }
  });
});

// Root ping
app.get('/', (req: Request, res: Response) => {
  res.json({
    service: 'Tejas AI Backend',
    status: 'running',
    version: CURRENT_APP_VERSION
  });
});

// ---------- Auto response-length detection ----------
type ResponseMode = 'tiny' | 'short' | 'normal' | 'detailed';

function detectResponseMode(query: string): {
  mode: ResponseMode;
  maxTokensToUse: number;
  temperatureToUse: number;
} {
  const q = query.toLowerCase();
  const wordCount = q.split(/\s+/).filter(Boolean).length;

  // User ne khud chhota jawab manga
  const wantsBrief = /(in short|briefly|short me|short mein|sankshep|ek line|one line|tldr|tl;dr|sirf batao|bas batao)/i.test(q);

  // User ne detail / code / lamba kaam manga (poore words match, "badalna" jaise words se galti nahi hogi)
  const wantsDetail =
    /\b(explain|explanation|detail|detailed|elaborate|step by step|steps|essay|story|article|tutorial|guide|compare|comparison|difference|write|code|program|script|function|algorithm|implement|debug|example|examples|vistar|samjhao|samjha|lamba|lambe|poori|puri|kaise banau|kaise banaye)\b/i.test(q) ||
    /(विस्तार|समझाओ|समझा|कैसे बनाऊ|लिखो|कोड)/.test(q) ||
    q.includes('```');

  const isGreeting = /^(hi|hii+|hello|hey|hlo|namaste|namaskar|thanks|thank you|ok|okay|hmm|good (morning|night|evening)|kaise ho|kya haal hai|suprabhat)[\s!.?]*$/i.test(q);

  if (wantsBrief && !wantsDetail) return { mode: 'tiny', maxTokensToUse: 150, temperatureToUse: 0.3 };
  if (wantsDetail || wordCount > 40) return { mode: 'detailed', maxTokensToUse: 1500, temperatureToUse: 0.7 };
  if (isGreeting || wordCount <= 3) return { mode: 'tiny', maxTokensToUse: 150, temperatureToUse: 0.4 };
  if (wordCount <= 12) return { mode: 'short', maxTokensToUse: 300, temperatureToUse: 0.5 };
  return { mode: 'normal', maxTokensToUse: 700, temperatureToUse: 0.6 };
}

// REST API Chat with Streaming Response capabilities
app.post('/api/chat', async (req: Request, res: Response) => {
  const { messages, userToken, systemPrompt, preferredModel, userProfile } = req.body;

  if (!messages || !Array.isArray(messages)) {
    res.status(400).json({ error: 'Invalid messages array' });
    return;
  }

  const activeToken = getCleanToken(userToken);

  // Set SSE Headers for real-time typewriter streaming
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendSSE = (event: string, data: any) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  // Validation: Model Access Restriction Logic (Guest vs Logged In)
  const isGuestUser =
    !userProfile ||
    userProfile.provider === 'guest' ||
    !userProfile.email ||
    userProfile.id === 'user_guest' ||
    String(userProfile.id).startsWith('guest_');

  if (preferredModel && preferredModel !== HF_MODEL && isGuestUser) {
    const restrictionMsg = `🔒 **Login Required for Advanced Models**\n\nAap abhi Guest mode me hain. \`${preferredModel}\` model use karne ke liye please upar **Sign In** button par click karke apna Google ya Email account connect karein.\n\n*Abhi aapka query free Tejas 1B model se process ho raha hai.*`;
    sendSSE('delta', { text: restrictionMsg });
    sendSSE('done', { model: HF_MODEL, restricted: true });
    res.end();
    return;
  }

  if (!activeToken) {
    const guidance = `👋 **Welcome to Tejas AI!**\n\nTo connect directly to live inference for \`${HF_MODEL}\`, you need a **Hugging Face Access Token**:\n\n1. Go to [Hugging Face Settings -> Access Tokens](https://huggingface.co/settings/tokens).\n2. Create a new token with **Read** permission.\n3. Make sure to accept Meta's license at [meta-llama/Llama-3.2-1B-Instruct](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct).\n4. Add your token in Railway as \`HF_TOKEN\`.\n\nOnce added, your queries will stream live from the model.`;
    const words = guidance.split(' ');
    for (let i = 0; i < words.length; i++) {
      sendSSE('delta', { text: words[i] + ' ' });
      await new Promise((r) => setTimeout(r, 22));
    }
    sendSSE('done', { model: HF_MODEL, tokenConfigured: false });
    res.end();
    return;
  }

  // ---- AUTO RESPONSE LENGTH (user ko koi setting nahi deni, query se khud decide hota hai) ----
  const lastUserMsg = [...messages].reverse().find((m: any) => m.role === 'user')?.content || '';
  const trimmedQuery = (typeof lastUserMsg === 'string' ? lastUserMsg : '').trim();
  const { mode, maxTokensToUse, temperatureToUse } = detectResponseMode(trimmedQuery);

  const basePrompt = systemPrompt?.trim() || 'You are Tejas, an intelligent, fast, and polite AI assistant.';
  const lengthRules: Record<ResponseMode, string> = {
    tiny:
      'LENGTH RULE: The user message is a greeting or a very short question. Reply in 1 short sentence (max 15-20 words). No lists, no filler.',
    short:
      'LENGTH RULE: This is a simple question. Reply in 1-3 short sentences. Give the direct answer first. No headings, no long lists.',
    normal:
      'LENGTH RULE: Reply in a short, clear paragraph or a few bullet points. Cover what was asked, without extra background or filler.',
    detailed:
      'LENGTH RULE: The user wants depth. Give a complete, well-structured answer with headings/bullets and examples or code where useful.',
  };
  const formattingRule =
    'FORMATTING RULE: When the answer has multiple sections or steps (detailed/normal answers), use short markdown headings and a relevant emoji at the start of each heading to make it scannable (e.g. "## 🚀 Getting Started"). For code, always use fenced code blocks with the correct language tag. Do not force headings/emojis on tiny one-line replies.';

  const effectiveSystemPrompt =
    `${basePrompt}\n\n${lengthRules[mode]}\n${formattingRule}\n` +
    `Always reply in the same language and script as the user (Hindi, Hinglish, English). Start directly with the answer.`;

  const formattedMessages = [
    {
      role: 'system',
      content: effectiveSystemPrompt
    },
    ...messages.map((m: any) => ({
      role: m.role === 'user' ? 'user' : 'assistant',
      content: m.content
    }))
  ];

  let selectedModel = preferredModel || HF_MODEL;
  if (selectedModel === 'meta-llama/Llama-3-70B-Instruct') {
    selectedModel = 'meta-llama/Llama-3.3-70B-Instruct';
  }

  try {
    let response = await fetch('https://router.huggingface.co/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${activeToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: selectedModel,
        messages: formattedMessages,
        max_tokens: maxTokensToUse,
        temperature: temperatureToUse,
        stream: true
      })
    });

    if (response.status === 503) {
      await new Promise((r) => setTimeout(r, 2500));
      response = await fetch('https://router.huggingface.co/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${activeToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: selectedModel,
          messages: formattedMessages,
          max_tokens: maxTokensToUse,
          temperature: temperatureToUse,
          stream: true
        })
      });
    }

    // Track any error text we read so we never try to read the body twice
    // (a Response body can only be consumed once — reading twice throws
    // "Body is unusable").
    let preReadErrorText: string | null = null;

    if (!response.ok && selectedModel !== FALLBACK_MODEL) {
      // Read the error body ONCE and keep it for later use
      preReadErrorText = await response.text();
      const isProviderOrNotFound =
        response.status === 400 ||
        response.status === 404 ||
        preReadErrorText.includes('not supported by any provider') ||
        preReadErrorText.includes('not supported') ||
        preReadErrorText.includes('Model not found');

      if (isProviderOrNotFound) {
        // Retry with fallback model — this gives us a fresh Response whose body is untouched
        selectedModel = FALLBACK_MODEL;
        response = await fetch('https://router.huggingface.co/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${activeToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: selectedModel,
            messages: formattedMessages,
            max_tokens: maxTokensToUse,
            temperature: temperatureToUse,
            stream: true
          })
        });
        preReadErrorText = null; // fresh response has its own body
      }
    }

    if (!response.ok) {
      // Use the error text we already read (if any), otherwise read now
      const errorText = preReadErrorText ?? (await response.text());
      let parsedMessage = errorText;
      try {
        const errJson = JSON.parse(errorText);
        if (errJson.error?.message) {
          parsedMessage = errJson.error.message;
        } else if (errJson.error) {
          parsedMessage = typeof errJson.error === 'string' ? errJson.error : JSON.stringify(errJson.error);
        }
      } catch {
        // use raw error text
      }

      sendSSE('error', {
        error: `Inference failed (${response.status}): ${parsedMessage}`,
        status: response.status
      });
      res.end();
      return;
    }
    if (!response.body) {
      sendSSE('error', { error: 'No response body stream from provider' });
      res.end();
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith(':')) continue;

        if (trimmed.startsWith('data: ')) {
          const dataStr = trimmed.slice(6).trim();
          if (dataStr === '[DONE]') {
            sendSSE('done', { model: selectedModel });
            break;
          }

          try {
            const parsed = JSON.parse(dataStr);
            const deltaContent = parsed.choices?.[0]?.delta?.content;
            if (deltaContent) {
              sendSSE('delta', { text: deltaContent });
            }
          } catch {
            // ignore malformed chunks
          }
        }
      }
    }

    sendSSE('done', { model: selectedModel });
    res.end();
  } catch (error: any) {
    sendSSE('error', { error: error.message || 'Internal server streaming error' });
    res.end();
  }
});

initDb()
  .catch((err) => console.error('Database init failed (guest mode chalta rahega):', err.message))
  .finally(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend server running on http://0.0.0.0:${PORT}`);
    });

    // Auto-cleanup: startup pe ek baar, phir har 6 ghante me.
    // - 30+ din purani guest/temp chats → delete
    // - 60+ din purani trashed chats → hard delete from DB
    const runCleanup = () => {
      purgeExpiredEphemeralChats()
        .then((count) => {
          if (count > 0) console.log(`Auto-cleanup: ${count} expired guest/temp chat(s) deleted.`);
        })
        .catch((err) => console.error('Ephemeral chat cleanup failed:', err.message));

      purgeOldChats()
        .then((count) => {
          if (count > 0) console.log(`Auto-cleanup: ${count} old trashed chat(s) hard-deleted.`);
        })
        .catch((err) => console.error('Old chats cleanup failed:', err.message));
    };
    runCleanup();
    setInterval(runCleanup, 6 * 60 * 60 * 1000);
  });