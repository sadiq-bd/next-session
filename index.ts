import 'server-only';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { cookies } from 'next/headers';

const secretKey = process.env.SESSION_SECRET;
const sessionValidity = process.env.SESSION_VALIDITY ?? '7d'; // default 7 days 
const sessionCookie = process.env.SESSION_COOKIE ?? 'app_session';

if (!secretKey) throw new Error('SESSION_SECRET is not defined');

const key = new TextEncoder().encode(secretKey);

// You can type the payload here if you want specific keys
export type SessionPayload = JWTPayload & {
  [key: string]: any;
};

export async function encrypt(payload: SessionPayload, validity?: string): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(validity ?? sessionValidity)
    .sign(key);
}

export async function decrypt(session: string | undefined): Promise<SessionPayload | null> {
  if (!session) return null;
  try {
    const { payload } = await jwtVerify<SessionPayload>(session, key, {
      algorithms: ['HS256'],
    });
    return payload;
  } catch {
    return null;
  }
}

export async function getSession<T = any>(key?: string, fallback: T | null = null): Promise<T | SessionPayload | null> {
  const session = (await cookies()).get(sessionCookie)?.value;
  const payload = await decrypt(session);

  if (key) return (payload?.[key] ?? fallback) as T;
  return payload;
}

export async function setSession(key: string, value: any, validity?: string): Promise<void> {
  const session = (await cookies()).get(sessionCookie)?.value;
  const payload = (await decrypt(session)) ?? {};

  payload[key] = value;
  const updatedSession = await encrypt(payload, validity);

  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

  const cookieStore = await cookies();
  cookieStore.set(sessionCookie, updatedSession, {
    httpOnly: true,
    secure: true,
    expires,
    sameSite: 'lax',
    path: '/',
  });
}

export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(sessionCookie);
}
