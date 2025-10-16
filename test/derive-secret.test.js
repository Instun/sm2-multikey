import assert from 'node:assert';
import { describe, it } from 'node:test';
import { SM2Multikey } from './config.js';
import { ArgumentError, KeyError, ErrorCodes } from '../lib/core/errors.js';

describe('SM2Multikey - deriveSecret', () => {
    describe('key agreement', () => {
        it('should derive shared secret between two key pairs', async () => {
            // Generate two key pairs (Alice and Bob)
            const alice = SM2Multikey.generate({ id: 'alice-key' });
            const bob = SM2Multikey.generate({ id: 'bob-key' });

            // Alice derives secret using Bob's public key
            const aliceSecret = await alice.deriveSecret({ publicKey: bob });
            
            // Bob derives secret using Alice's public key
            const bobSecret = await bob.deriveSecret({ publicKey: alice });

            // Both should derive the same shared secret
            assert(aliceSecret instanceof Uint8Array);
            assert(bobSecret instanceof Uint8Array);
            assert.strictEqual(aliceSecret.length, 32);
            assert.strictEqual(bobSecret.length, 32);
            assert(Buffer.from(aliceSecret).equals(Buffer.from(bobSecret)));
        });

        it('should derive secret using remotePublicKey parameter (backward compatibility)', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            const secret1 = await alice.deriveSecret({ publicKey: bob });
            const secret2 = await alice.deriveSecret({ remotePublicKey: bob });

            assert(Buffer.from(secret1).equals(Buffer.from(secret2)));
        });

        it('should derive secret with raw public key object', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            // Test with raw key object
            const bobExported = bob.export({ publicKey: true });
            const secret1 = await alice.deriveSecret({ publicKey: bob });
            const secret2 = await alice.deriveSecret({ publicKey: bobExported });

            assert(Buffer.from(secret1).equals(Buffer.from(secret2)));
        });

        it('should generate different secrets for different key pairs', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();
            const charlie = SM2Multikey.generate();

            const aliceBobSecret = await alice.deriveSecret({ publicKey: bob });
            const aliceCharlieSecret = await alice.deriveSecret({ publicKey: charlie });

            assert(!Buffer.from(aliceBobSecret).equals(Buffer.from(aliceCharlieSecret)));
        });

        it('should be deterministic - same keys produce same secret', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            const secret1 = await alice.deriveSecret({ publicKey: bob });
            const secret2 = await alice.deriveSecret({ publicKey: bob });

            assert(Buffer.from(secret1).equals(Buffer.from(secret2)));
        });
    });

    describe('keyAgreement property', () => {
        it('should indicate support for key agreement', () => {
            const key = SM2Multikey.generate();
            assert.strictEqual(key.keyAgreement, true);
        });

        it('should indicate support even without private key', () => {
            const key = SM2Multikey.generate();
            const exported = key.export({ publicKey: true, secretKey: false });
            const publicOnlyKey = SM2Multikey.from(exported);
            
            assert.strictEqual(publicOnlyKey.keyAgreement, true);
        });
    });

    describe('error handling', () => {
        it('should throw error when no private key available', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();
            
            // Create public-only key
            const alicePublicOnly = SM2Multikey.from(
                alice.export({ publicKey: true, secretKey: false })
            );

            await assert.rejects(
                async () => await alicePublicOnly.deriveSecret({ publicKey: bob }),
                {
                    name: 'KeyError',
                    code: ErrorCodes.ERR_KEY_NOT_FOUND,
                    message: /Private key required/
                }
            );
        });

        it('should throw error when no remote public key provided', async () => {
            const alice = SM2Multikey.generate();

            await assert.rejects(
                async () => await alice.deriveSecret({}),
                {
                    name: 'ArgumentError',
                    code: ErrorCodes.ERR_ARGUMENT_INVALID,
                    message: /Remote public key must be provided/
                }
            );
        });

        it('should throw error when both publicKey and remotePublicKey provided', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            await assert.rejects(
                async () => await alice.deriveSecret({ 
                    publicKey: bob, 
                    remotePublicKey: bob 
                }),
                {
                    name: 'ArgumentError',
                    code: ErrorCodes.ERR_ARGUMENT_INVALID,
                    message: /Only one of.*must be given/
                }
            );
        });

        it('should throw error when remote key has no public key', async () => {
            const alice = SM2Multikey.generate();
            const bob = new SM2Multikey(); // Empty key

            await assert.rejects(
                async () => await alice.deriveSecret({ publicKey: bob }),
                {
                    name: 'KeyError',
                    code: ErrorCodes.ERR_KEY_NOT_FOUND,
                    message: /Remote key has no public key/
                }
            );
        });

        it('should throw error with invalid remote key format', async () => {
            const alice = SM2Multikey.generate();

            await assert.rejects(
                async () => await alice.deriveSecret({ 
                    publicKey: { invalidKey: true } 
                }),
                {
                    name: 'ArgumentError',
                    code: ErrorCodes.ERR_ARGUMENT_INVALID,
                    message: /Invalid remote key format/
                }
            );
        });
    });

    describe('performance', () => {
        it('should complete key agreement in reasonable time', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            const start = Date.now();
            await alice.deriveSecret({ publicKey: bob });
            const duration = Date.now() - start;

            // Should complete within 100ms (generous timeout)
            assert(duration < 100, `Key agreement took ${duration}ms, expected < 100ms`);
        });

        it('should handle multiple concurrent derivations', async () => {
            const alice = SM2Multikey.generate();
            const keys = Array.from({ length: 10 }, () => SM2Multikey.generate());

            const start = Date.now();
            const secrets = await Promise.all(
                keys.map(key => alice.deriveSecret({ publicKey: key }))
            );
            const duration = Date.now() - start;

            assert.strictEqual(secrets.length, 10);
            assert(duration < 1000, `Concurrent derivations took ${duration}ms, expected < 1000ms`);
            
            // Verify all secrets are different
            const secretSet = new Set(secrets.map(s => Buffer.from(s).toString('hex')));
            assert.strictEqual(secretSet.size, 10, 'All secrets should be unique');
        });
    });

    describe('interoperability', () => {
        it('should work with keys from export/import cycle', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            // Export and re-import Alice's key
            const aliceExported = alice.export({ publicKey: true, secretKey: true });
            const aliceReimported = SM2Multikey.from(aliceExported);

            const secret1 = await alice.deriveSecret({ publicKey: bob });
            const secret2 = await aliceReimported.deriveSecret({ publicKey: bob });

            assert(Buffer.from(secret1).equals(Buffer.from(secret2)));
        });

        it('should work with keys from JWK format', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            // Convert Bob to JWK and back
            const bobJwk = SM2Multikey.toJwk({ keyPair: bob, secretKey: false });
            const bobFromJwk = SM2Multikey.fromJwk({ jwk: bobJwk });

            const secret1 = await alice.deriveSecret({ publicKey: bob });
            const secret2 = await alice.deriveSecret({ publicKey: bobFromJwk });

            assert(Buffer.from(secret1).equals(Buffer.from(secret2)));
        });
    });

    describe('edge cases', () => {
        it('should handle keys with IDs and controllers', async () => {
            const alice = SM2Multikey.generate({ 
                id: 'did:example:alice#key-1',
                controller: 'did:example:alice'
            });
            const bob = SM2Multikey.generate({
                id: 'did:example:bob#key-1', 
                controller: 'did:example:bob'
            });

            const secret = await alice.deriveSecret({ publicKey: bob });
            assert(secret instanceof Uint8Array);
            assert.strictEqual(secret.length, 32);
        });

        it('should handle repeated derivations with same keys', async () => {
            const alice = SM2Multikey.generate();
            const bob = SM2Multikey.generate();

            const secrets = await Promise.all([
                alice.deriveSecret({ publicKey: bob }),
                alice.deriveSecret({ publicKey: bob }),
                alice.deriveSecret({ publicKey: bob })
            ]);

            // All should be identical
            assert(Buffer.from(secrets[0]).equals(Buffer.from(secrets[1])));
            assert(Buffer.from(secrets[1]).equals(Buffer.from(secrets[2])));
        });
    });
});