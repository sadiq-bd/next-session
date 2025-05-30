import 'server-only';
import { JWTPayload } from 'jose';
export type SessionPayload = JWTPayload & {
    [key: string]: any;
};
export declare function encrypt(payload: SessionPayload, validity?: string): Promise<string>;
export declare function decrypt(session: string | undefined): Promise<SessionPayload | null>;
export declare function getSession<T = any>(key?: string, fallback?: T | null): Promise<T | SessionPayload | null>;
export declare function setSession(key: string, value: any, validity?: string): Promise<void>;
export declare function destroySession(): Promise<void>;
