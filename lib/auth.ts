import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from './env';
import { db } from './db';
import { NextRequest } from 'next/server';

// ─── Password Hashing ───────────────────────────────────────────

export async function hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
}

// ─── JWT ─────────────────────────────────────────────────────────

interface JwtPayload {
    userId: string;
    email: string;
    role: string;
}

export function signToken(payload: JwtPayload): string {
    return jwt.sign(payload as any, env.JWT_SECRET, {
        expiresIn: env.JWT_EXPIRY as any,
    });
}

export function verifyToken(token: string): JwtPayload | null {
    try {
        return jwt.verify(token, env.JWT_SECRET) as JwtPayload;
    } catch {
        return null;
    }
}

// ─── Auth Middleware ──────────────────────────────────────────────

export interface AuthUser {
    userId: string;
    email: string;
    role: string;
}

export async function getAuthUser(request: NextRequest): Promise<AuthUser | null> {
    // Check Authorization header
    const authHeader = request.headers.get('authorization');
    if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.slice(7);

        // Check if it's an API key (starts with sk-recall-)
        if (token.startsWith('sk-recall-')) {
            return authenticateApiKey(token);
        }

        // Otherwise treat as JWT
        const payload = verifyToken(token);
        if (payload) return payload;
    }

    // Check cookie
    const cookieToken = request.cookies.get('recall-token')?.value;
    if (cookieToken) {
        const payload = verifyToken(cookieToken);
        if (payload) return payload;
    }

    return null;
}

async function authenticateApiKey(key: string): Promise<AuthUser | null> {
    try {
        const apiKeys = await db.apiKey.findMany({
            where: { prefix: key.slice(0, 15) },
            include: { user: true },
        });

        for (const apiKey of apiKeys) {
            const isMatch = await bcrypt.compare(key, apiKey.keyHash);
            if (!isMatch) continue;

            await db.apiKey.update({
                where: { id: apiKey.id },
                data: { lastUsed: new Date() },
            });

            return { userId: apiKey.userId, email: apiKey.user.email, role: apiKey.user.role };
        }

        return null;
    } catch {
        return null;
    }
}

// ─── Require Auth Helper ─────────────────────────────────────────

export async function requireAuth(request: NextRequest): Promise<AuthUser> {
    const user = await getAuthUser(request);
    if (!user) {
        throw new AuthError('Unauthorized');
    }
    return user;
}

export class AuthError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AuthError';
    }
}
