var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var _a, _b;
import 'server-only';
import { SignJWT, jwtVerify } from 'jose';
import { cookies } from 'next/headers';
const secretKey = process.env.SESSION_SECRET;
const sessionValidity = (_a = process.env.SESSION_VALIDITY) !== null && _a !== void 0 ? _a : '7d'; // default 7 days 
const sessionCookie = (_b = process.env.SESSION_COOKIE) !== null && _b !== void 0 ? _b : 'app_session';
if (!secretKey)
    throw new Error('SESSION_SECRET is not defined');
const key = new TextEncoder().encode(secretKey);
export function encrypt(payload, validity) {
    return __awaiter(this, void 0, void 0, function* () {
        return new SignJWT(payload)
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setExpirationTime(validity !== null && validity !== void 0 ? validity : sessionValidity)
            .sign(key);
    });
}
export function decrypt(session) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!session)
            return null;
        try {
            const { payload } = yield jwtVerify(session, key, {
                algorithms: ['HS256'],
            });
            return payload;
        }
        catch (_a) {
            return null;
        }
    });
}
export function getSession(key_1) {
    return __awaiter(this, arguments, void 0, function* (key, fallback = null) {
        var _a, _b;
        const session = (_a = (yield cookies()).get(sessionCookie)) === null || _a === void 0 ? void 0 : _a.value;
        const payload = yield decrypt(session);
        if (key)
            return ((_b = payload === null || payload === void 0 ? void 0 : payload[key]) !== null && _b !== void 0 ? _b : fallback);
        return payload;
    });
}
export function setSession(key, value, validity) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, _b;
        const session = (_a = (yield cookies()).get(sessionCookie)) === null || _a === void 0 ? void 0 : _a.value;
        const payload = (_b = (yield decrypt(session))) !== null && _b !== void 0 ? _b : {};
        payload[key] = value;
        const updatedSession = yield encrypt(payload, validity);
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        const cookieStore = yield cookies();
        cookieStore.set(sessionCookie, updatedSession, {
            httpOnly: true,
            secure: true,
            expires,
            sameSite: 'lax',
            path: '/',
        });
    });
}
export function destroySession() {
    return __awaiter(this, void 0, void 0, function* () {
        const cookieStore = yield cookies();
        cookieStore.delete(sessionCookie);
    });
}
