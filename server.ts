import express, { Request, Response } from 'express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
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

// Enable CORS for external access (allow Vercel, localhost, Android WebView)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

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

// REST API Chat with Streaming Response capabilities
app.post('/api/chat', async (req: Request, res: Response) => {
  const { messages, userToken, systemPrompt, preferredModel, responseStyle, userProfile } = req.body;

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

  // Detect if query is a short/simple question to enforce extreme conciseness
  const lastUserMsg = [...messages].reverse().find((m: any) => m.role === 'user')?.content || '';
  const trimmedQuery = (typeof lastUserMsg === 'string' ? lastUserMsg : '').trim();
  const wordCount = trimmedQuery.split(/\s+/).filter(Boolean).length;
  const isExplicitlyDetailed = /(explain|detail|elaborate|code|function|program|script|steps|step by step|list|compare|essay|story|vistar|lambe me|bada|kripya vistar|guide)/i.test(trimmedQuery);
  const isUltraShort = !isExplicitlyDetailed && (wordCount <= 6 || trimmedQuery.length <= 35);
  const isShortQuery = !isExplicitlyDetailed && (wordCount <= 14 || trimmedQuery.length <= 80);

  let maxTokensToUse = 1024;
  let temperatureToUse = 0.7;

  if (responseStyle !== 'detailed') {
    if (isUltraShort) {
      maxTokensToUse = 60;
      temperatureToUse = 0.3;
    } else if (isShortQuery) {
      maxTokensToUse = 120;
      temperatureToUse = 0.4;
    }
  }

  // Base prompt and strict query-adaptive brevity
  const basePrompt = systemPrompt?.trim() || 'You are Tejas, an intelligent, fast, and polite AI assistant.';
  let effectiveSystemPrompt = basePrompt;

  if (responseStyle === 'detailed') {
    effectiveSystemPrompt += '\n\nStyle: Provide comprehensive, detailed explanations with complete context and examples.';
  } else if (isUltraShort || isShortQuery) {
    effectiveSystemPrompt +=
      `\n\nCRITICAL CONCISENESS RULE (MANDATORY):\n` +
      `The user's query is very short: "${trimmedQuery}".\n` +
      `- You MUST answer in ONLY 1 or 2 short sentences (maximum 20-25 words).\n` +
      `- NEVER write long paragraphs, history, bullet points, or filler.\n` +
      `- Do not repeat the question. Give the direct answer immediately.\n` +
      `- Language: Match the user's language (Hindi, Hinglish, English) naturally and succinctly.`;
  } else {
    effectiveSystemPrompt +=
      `\n\nMANDATORY CONCISENESS & LENGTH RULES:\n` +
      `1. Query-Adaptive Length: Directly match your response length to query complexity.\n` +
      `   - For quick facts, casual questions, or greetings: Answer in 1 to 3 short sentences.\n` +
      `   - For coding, complex, or multi-step questions: Provide structured, clean explanations.\n` +
      `2. No Fluff: Start directly with the answer. Avoid generic intros.\n` +
      `3. Language Tone: Reply naturally in the same language as the user without adding unnecessary bloat.`;
  }

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

    if (!response.ok && selectedModel !== FALLBACK_MODEL) {
      const initialError = await response.text();
      const isProviderOrNotFound =
        response.status === 400 ||
        response.status === 404 ||
        initialError.includes('not supported by any provider') ||
        initialError.includes('not supported') ||
        initialError.includes('Model not found');

      if (isProviderOrNotFound) {
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
      }
    }

    if (!response.ok) {
      const errorText = await response.text();
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend server running on http://0.0.0.0:${PORT}`);
});
