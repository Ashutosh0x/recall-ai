import crypto from 'node:crypto';

export function verifyHmacSignature(payload: string, providedSignature: string | null, secret: string | undefined): boolean {
    if (!secret || !providedSignature) return false;

    const normalized = providedSignature.replace(/^sha256=/, '');
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');

    const normalizedBuffer = Buffer.from(normalized, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');

    if (normalizedBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(normalizedBuffer, expectedBuffer);
}
