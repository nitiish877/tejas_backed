import admin from 'firebase-admin';

const projectId = (process.env.FIREBASE_PROJECT_ID || '').trim();
const clientEmail = (process.env.FIREBASE_CLIENT_EMAIL || '').trim();
const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '')
  .replace(/\\n/g, '\n')  // Railway me \n literal aata hai, usko real newline me convert karo
  .trim();

export const firebaseAdminEnabled = Boolean(projectId && clientEmail && privateKey);

if (firebaseAdminEnabled) {
  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
      console.log('Firebase Admin initialized.');
    }
  } catch (err: any) {
    console.error('Firebase Admin init failed:', err.message);
  }
} else {
  console.warn('Firebase Admin not configured (missing FIREBASE_* env vars). Google sign-in disabled.');
}

export const firebaseAuth = firebaseAdminEnabled ? admin.auth() : null;