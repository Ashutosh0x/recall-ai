import bcrypt from 'bcryptjs';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { jsonResponse, errorResponse } from '@/lib/api-helpers';
import { db } from '@/lib/db';
import { requireAuth, AuthError } from '@/lib/auth';

const createApiKeySchema = z.object({
    name: z.string().trim().min(1).max(80),
});

export async function GET(request: NextRequest) {
    try {
        const user = await requireAuth(request);
        const keys = await db.apiKey.findMany({
            where: { userId: user.userId },
            orderBy: { createdAt: 'desc' },
        });

        return jsonResponse({
            data: keys.map((key) => ({
                id: key.id,
                name: key.name,
                prefix: `${key.prefix}****`,
                created_at: key.createdAt.toISOString(),
                last_used: key.lastUsed?.toISOString() ?? null,
            })),
        });
    } catch (error) {
        if (error instanceof AuthError) {
            return errorResponse(error.message, 401);
        }
        console.error('[API Keys] Failed to list keys', error);
        return errorResponse('Failed to list API keys', 500);
    }
}

export async function POST(request: NextRequest) {
    try {
        const user = await requireAuth(request);
        const body = await request.json();
        const parsed = createApiKeySchema.safeParse(body);

        if (!parsed.success) {
            return errorResponse('Invalid request body', 400);
        }

        const rawKey = `sk-recall-${crypto.randomUUID()}${crypto.randomUUID().replace(/-/g, '')}`;
        const keyHash = await bcrypt.hash(rawKey, 12);

        const apiKey = await db.apiKey.create({
            data: {
                userId: user.userId,
                name: parsed.data.name,
                keyHash,
                prefix: rawKey.slice(0, 15),
            },
        });

        return jsonResponse({
            data: {
                id: apiKey.id,
                name: apiKey.name,
                key: rawKey,
                prefix: `${apiKey.prefix}****`,
                created_at: apiKey.createdAt.toISOString(),
            },
        }, 201);
    } catch (error) {
        if (error instanceof AuthError) {
            return errorResponse(error.message, 401);
        }
        console.error('[API Keys] Failed to create key', error);
        return errorResponse('Failed to create API key', 500);
    }
}
