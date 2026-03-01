import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyHmacSignature } from '@/lib/webhook';

describe('verifyHmacSignature', () => {
    it('accepts valid signatures', () => {
        const payload = JSON.stringify({ test: true });
        const secret = 'secret123';
        const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');

        expect(verifyHmacSignature(payload, signature, secret)).toBe(true);
    });

    it('rejects invalid signatures', () => {
        const payload = JSON.stringify({ test: true });
        expect(verifyHmacSignature(payload, 'bad', 'secret123')).toBe(false);
    });

    it('rejects missing secret or signature', () => {
        const payload = '{}';
        expect(verifyHmacSignature(payload, null, 'secret123')).toBe(false);
        expect(verifyHmacSignature(payload, 'abc', undefined)).toBe(false);
    });
});
