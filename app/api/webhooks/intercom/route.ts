import { errorResponse, jsonResponse } from '@/lib/api-helpers';
import { verifyHmacSignature } from '@/lib/webhook';

export async function POST(request: Request) {
    const payload = await request.text();
    const valid = verifyHmacSignature(
        payload,
        request.headers.get('x-signature'),
        process.env.INTERCOM_WEBHOOK_SECRET,
    );

    if (!valid) {
        return errorResponse('Invalid webhook signature', 401);
    }

    try {
        const body = JSON.parse(payload) as { topic?: string };
        return jsonResponse({ data: { source: 'intercom', event: body.topic ?? null, processed: true } });
    } catch {
        return errorResponse('Invalid JSON payload', 400);
    }
}
