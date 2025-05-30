import 'server-only'
import { SignJWT, jwtVerify } from 'jose'
import { cookies } from 'next/headers'
 
const secretKey = process.env.SESSION_SECRET;
 
export async function encrypt(payload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(new TextEncoder().encode(secretKey));
}
 
export async function decrypt(session) {
  try {
    const { payload } = await jwtVerify(session, new TextEncoder().encode(secretKey), {
      algorithms: ['HS256'],
    })
    return payload;
  } catch (error) {
    // console.log('Failed to verify session');
    return null;
  }
}

export async function getSession(key, fallback = null) {
  const session = (await cookies()).get('app_session')?.value;
  const payload = await decrypt(session);
  // @ts-ignore
  if (key) return payload[key] ?? fallback;
  return payload;
}

export async function setSession(key, value) {
  const session = (await cookies()).get('app_session')?.value;
  let payload = (await decrypt(session)) ?? {};
 
  payload[key] = value;

  const updatedSession = await encrypt(payload);
   
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
 
  const cookieStore = await cookies();
  cookieStore.set('app_session', updatedSession, {
    httpOnly: true,
    secure: true,
    expires: expires,
    sameSite: 'lax',
    path: '/',
  });

}

export async function destroySession() {
  const cookieStore = await cookies()
  cookieStore.delete('session')
}
