import assert from 'node:assert';
import { describe, it } from 'node:test';
import { SM2Multikey } from './config.js';
import { SM2Error, StateError, ErrorCodes } from '../lib/core/errors.js';

describe('SM2Multikey', () => {
    describe('constructor', () => {
        it('should create an empty instance', () => {
            const key = new SM2Multikey();
            assert.strictEqual(key.publicKey, null);
            assert.strictEqual(key.secretKey, null);
            assert.strictEqual(key.id, null);
            assert.strictEqual(key.controller, null);
        });
    });

    describe('generate', () => {
        it('should generate key pair without options', () => {
            const key = SM2Multikey.generate();
            assert(key instanceof SM2Multikey);
            assert(Buffer.isBuffer(key.publicKey));
            assert(Buffer.isBuffer(key.secretKey));
            assert.strictEqual(key.publicKey.length, 64); // SM2 公钥是 64 字节
            assert.strictEqual(key.secretKey.length, 32); // SM2 私钥是 32 字节
            assert(!key.id);
            assert(!key.controller);
        });

        it('should generate key pair with id', () => {
            const id = 'test-id';
            const key = SM2Multikey.generate({ id });
            assert.strictEqual(key.id, id);
            assert(!key.controller);
        });

        it('should generate key pair with controller', () => {
            const controller = 'test-controller';
            const key = SM2Multikey.generate({ controller });
            assert.strictEqual(key.controller, controller);
            assert(key.id.startsWith(controller + '#'));
        });

        it('should throw error with invalid id', () => {
            assert.throws(
                () => SM2Multikey.generate({ id: 123 }),
                {
                    name: 'ArgumentError',
                    code: ErrorCodes.ERR_ARGUMENT_INVALID
                }
            );
        });

        it('should throw error with invalid controller', () => {
            assert.throws(
                () => SM2Multikey.generate({ controller: 123 }),
                {
                    name: 'ArgumentError',
                    code: ErrorCodes.ERR_ARGUMENT_INVALID
                }
            );
        });
    });

    describe('export', () => {
        it('should export public key by default', () => {
            const key = SM2Multikey.generate();
            const exported = key.export();
            assert.strictEqual(exported.type, 'Multikey');
            assert(typeof exported.publicKeyMultibase === 'string');
            assert(!exported.secretKeyMultibase);
            assert(exported.publicKeyMultibase.startsWith('z')); // multibase 编码以 z 开头
        });

        it('should export with context when includeContext is true', () => {
            const key = SM2Multikey.generate();
            const exported = key.export({ includeContext: true });
            assert(exported['@context']);
        });

        it('should export raw keys when raw is true', () => {
            const key = SM2Multikey.generate();
            const exported = key.export({ raw: true, secretKey: true });
            assert(Buffer.isBuffer(exported.publicKey));
            assert(Buffer.isBuffer(exported.secretKey));
            assert.strictEqual(exported.publicKey.length, 64);
            assert.strictEqual(exported.secretKey.length, 32);
        });

        it('should export private key when secretKey is true', () => {
            const key = SM2Multikey.generate();
            const exported = key.export({ secretKey: true });
            assert(typeof exported.secretKeyMultibase === 'string');
            assert(exported.secretKeyMultibase.startsWith('z'));
        });
    });

    describe('signer and verifier', () => {
        it('should sign and verify message', () => {
            const key = SM2Multikey.generate();
            const message = Buffer.from('test message');

            const { sign } = key.signer();
            const signature = sign({ data: message });
            assert(Buffer.isBuffer(signature));

            const { verify } = key.verifier();
            const valid = verify({ data: message, signature });
            assert.strictEqual(valid, true);
        });

        it('should fail verification with wrong message', () => {
            const key = SM2Multikey.generate();
            const message = Buffer.from('test message');
            const wrongMessage = Buffer.from('wrong message');

            const { sign } = key.signer();
            const signature = sign({ data: message });

            const { verify } = key.verifier();
            const valid = verify({ data: wrongMessage, signature });
            assert.strictEqual(valid, false);
        });

        it('should throw error when signing without private key', () => {
            const key = new SM2Multikey();
            assert.throws(
                () => key.signer(),
                {
                    name: 'KeyError',
                    code: ErrorCodes.ERR_KEY_NOT_FOUND
                }
            );
        });

        it('should throw error when verifying without public key', () => {
            const key = new SM2Multikey();
            assert.throws(
                () => key.verifier(),
                {
                    name: 'KeyError',
                    code: ErrorCodes.ERR_KEY_NOT_FOUND
                }
            );
        });
    });

    describe('static signature test vectors', () => {
        const testVectors = [
            {
                name: 'Test Vector 1',
                key: {
                    '@context': 'https://w3id.org/security/multikey/v1',
                    publicKeyMultibase: 'zEPJcHCTZ5V4jR1cFb9ptYk22SRRZb56VzCLm3cQ8KtYX4Qsc',
                    secretKeyMultibase: 'z4G1CrmL4cxVjko4gSkeRcUSa4ufxmaSvEnebDRgqLFdf89j',
                    type: 'Multikey'
                },
                jwk: {
                    kty: 'EC',
                    crv: 'SM2',
                    x: 'F4yXvv-AfYpmT1VN5ph8rX_qw9lB-fryHLfh6H0tgys',
                    y: '1nc7Whh5v1JBv6zueWxE4H8yFgLIJOL1aZ0w5Pid4vc',
                    d: 'EdUqYVq1VUsU8AS5hp_R2FIbBKI0pXOmHK1ttiabuqY'
                },
                message: Buffer.from('signature test'),
                signature: Buffer.from('e9fa0b03ac51ed59e4e2997d35e3dc4c22852320d340dd6ed0e927c467a23d3b57d81e90397b77d216b5f654ca1bb98b913f4575328e254cc0278b1cebf51567', 'hex'),
            },
            {
                name: 'Test Vector 2 - Empty Message',
                key: {
                    '@context': 'https://w3id.org/security/multikey/v1',
                    publicKeyMultibase: 'zEPJc1vCfbG2aoZn8f3U8ggYRL4ZFfF63ZA3qFSk81WJxnCQr',
                    secretKeyMultibase: 'z4G1QMJTvRj2rfntiUQtRBu9MfEEZ3kAuodAmkTergjDotXM',
                    type: 'Multikey'
                },
                jwk: {
                    kty: 'EC',
                    crv: 'SM2',
                    x: 'NIMpjy0M25izi2DrQLhQBlL8b45Lt9a0FzfELdpdO0s',
                    y: 'NXstrSPtSp1cZzvupZ8C68FCgSQhZbuGYLorP6F1N2w',
                    d: 'vJUwfRiA7lDOnJEmJmCMWDvZ5EScnaieKNuqie5GnHw'
                },
                message: Buffer.from(''),
                signature: Buffer.from('dc9b98def44a5352821cec5484e211fab816b1e6f0c187006d9121ad341755aa4bc264212711eed6e23afe1ef2cd455ea0460ad4f65c4dcd4a0c24326132173c', 'hex'),
            },
            {
                name: 'Test Vector 3 - Chinese Characters',
                key: {
                    '@context': 'https://w3id.org/security/multikey/v1',
                    publicKeyMultibase: 'zEPJbzijVS23WTMM6XU5cAnmeeFGXffrnM34ZB263TFYFgwKf',
                    secretKeyMultibase: 'z4G1HCbWixEZMhtxE4K62HcKgKoa8Pnv3Sma7ZvotCm1PHLa',
                    type: 'Multikey'
                },
                jwk: {
                    kty: 'EC',
                    crv: 'SM2',
                    x: 'IrdcBbrVDB71hRm-XbDbUxARW6Tz9NGnnUj_6naue6o',
                    y: 'E0eh47bvx-CtJEl8jqeDUX51OTYsJfc0QFNCC8M0jjQ',
                    d: 'UlhuI68hVcqcGRBKpuyrnUwLJO_AdU6sh--_tO7vmd8'
                },
                message: Buffer.from('测试签名'),
                signature: Buffer.from('a18fec2c91bf04f211594659e077b0972f1bf7e4a11b46b49a4214a5fdc5bfac0aa26c3849bcdbf14c4cbcb461db85ac6ac9c549897b180206b8a24db7a57bea', 'hex'),
            }
        ];

        testVectors.forEach(vector => {
            it(vector.name, () => {
                const key = SM2Multikey.from(vector.key);
                assert.deepEqual(SM2Multikey.toJwk({
                    keyPair: key,
                    secretKey: true
                }), vector.jwk);

                const { sign } = key.signer();
                const signature = sign({ data: vector.message });
                assert(Buffer.isBuffer(signature));
                assert(signature.length > 0);

                const { verify } = key.verifier();
                const valid = verify({ data: vector.message, signature: vector.signature });
                assert.strictEqual(valid, true);
            });
        });

        it('should fail verification with wrong message', () => {
            const vector = testVectors[0];
            const key = SM2Multikey.from(vector.key);
            const wrongMessage = Buffer.from('wrong message');
            const { verify } = key.verifier();
            const valid = verify({ data: wrongMessage, signature: vector.signature });
            assert.strictEqual(valid, false);
        });

        it('should throw error when signing without private key', () => {
            const key = new SM2Multikey();
            assert.throws(
                () => key.signer(),
                {
                    name: 'KeyError',
                    code: 'ERR_KEY_NOT_FOUND'
                }
            );
        });

        it('should throw error when verifying without public key', () => {
            const key = new SM2Multikey();
            assert.throws(
                () => key.verifier(),
                {
                    name: 'KeyError',
                    code: 'ERR_KEY_NOT_FOUND'
                }
            );
        });

        it('should fail verification with modified signature', () => {
            const vector = testVectors[0];
            const key = SM2Multikey.from(vector.key);
            const modifiedSignature = Buffer.from(vector.signature);
            modifiedSignature[0] ^= 1;

            const { verify } = key.verifier();
            const valid = verify({ data: vector.message, signature: modifiedSignature });
            assert.strictEqual(valid, false);
        });
    });

    describe('SM2Multikey signature test vectors', () => {
        const signatureTestVectors = [
            {
                name: 'Test Vector 1',
                publicKey: Buffer.from('d53d4e4db80659384189cc0558a793055e04871ad358f3b9d45fb2704a430f69044ce9cc450d1bd97b070d14e0d04add94a2fbfba6deefb2695b539c96c30fa3', 'hex'),
                privateKey: Buffer.from('c5f1ce03972ce958924e44f79bdff5a4c0b6e47e7476c1b515a8dedb65ccff8b', 'hex'),
                message: Buffer.from('signature test'),
            },
            {
                name: 'Test Vector 2 - Empty Message',
                publicKey: Buffer.from('ff68613076bdcf7b687130bbe2e2f879c78538ca814fcc9436af4a37698e198e773337445fe94de35afc562c33e534a45ce7ae91d71c1246348f5439d3aeda65', 'hex'),
                privateKey: Buffer.from('3a0e3370bb75ed443c6050990ce6efe889642d6259fe23498369fe6792e4e4f2', 'hex'),
                message: Buffer.from(''),
            },
            {
                name: 'Test Vector 3 - Chinese Characters',
                publicKey: Buffer.from('3d150fac88f1d1ed7ff389ad0b50c40478ec40fa78bab26cef70bfd8c38b09ad35c9894a1a1b2938ff70d74ef03d748e1d25116c026380588fae625a5e83e171', 'hex'),
                privateKey: Buffer.from('ea16feca9ef1d30deee849588c846dd4d72aa15902dda16df8f3649cd876577c', 'hex'),
                message: Buffer.from('测试签名'),
            }
        ];

        for (const vector of signatureTestVectors) {
            it(`should sign and verify ${vector.name}`, () => {
                const key = new SM2Multikey();
                key.publicKey = vector.publicKey;
                key.secretKey = vector.privateKey;

                const { sign } = key.signer();
                const signature = sign({ data: vector.message });

                const { verify } = key.verifier();
                const valid = verify({ data: vector.message, signature });

                assert.strictEqual(valid, true);
            });

            it(`should fail verification with wrong message for ${vector.name}`, () => {
                const key = new SM2Multikey();
                key.publicKey = vector.publicKey;
                key.secretKey = vector.privateKey;

                const { sign } = key.signer();
                const signature = sign({ data: vector.message });

                const { verify } = key.verifier();
                const wrongMessage = Buffer.from('wrong message');
                const valid = verify({ data: wrongMessage, signature });

                assert.strictEqual(valid, false);
            });
        }
    });

    describe('SM2Multikey signature test vectors', () => {
        const testVectors = [
            // Test Vector 1 - Basic ASCII message
            {
                name: 'Test Vector 1',
                key: {
                    type: 'Multikey',
                    publicKey: Buffer.from('f89c153dcc7885a853f232ec4ad97f2cf7b432cf298cabe7ed6de870cc2ef976ceff8b867d2277317576674fb1195b905c4b792ea18a82cf2e461bcc39ac5682', 'hex'),
                    secretKey: Buffer.from('d422f0b3bdb8727609411795c666ecc629d6916d89208dd1133a7084c901a2ca', 'hex'),
                },
                message: Buffer.from('signature test'),
                signature: Buffer.from('679e45cd660939c4ebe6422ab2598833244a9d905c0529627b17a7bc59e3a6b545c2752cff032eef7d3786a9cba034df5b1b682670b3b05ed112c35a2c2b0919', 'hex'),
            },
            {
                name: 'Test Vector 2 - Empty Message',
                key: {
                    type: 'Multikey',
                    publicKey: Buffer.from('2d9ca5b4051e88331992a2f77fa4242d9dc401b7b40c30f06795d243a645693824d4365293c4ed340b931922ffcd21bd8e5fb235576be105f42861c7a53709f6', 'hex'),
                    secretKey: Buffer.from('3a2adc61ae3a7c6e25bd96d323f61db7b248d114b86706267847205b5c29b439', 'hex'),
                },
                message: Buffer.from(''),
                signature: Buffer.from('5e69bf863bdd8d6ccb4e5aebc25bddd99583ac79e4fa9218905b6cee3b963f32c2fbdff6f9a2bce5516b256d17b206664ed8c13adba0b54e05edc4f95c66220d', 'hex'),
            },
            {
                name: 'Test Vector 3 - Chinese Characters',
                key: {
                    type: 'Multikey',
                    publicKey: Buffer.from('ece6bfa023a94c385c3452320dd7269be6f27ae06d4d70c47a9bdc54ecc0cc8e102521d4c9e66b07c2b163ee203fa3f60e65179d73dc24e2f6c7568d623778bc', 'hex'),
                    secretKey: Buffer.from('deeb0a6ffc50262abd04710f3dfadc4a3a3d18de8f9f99e087e6b83880ee9609', 'hex'),
                },
                message: Buffer.from('测试签名'),
                signature: Buffer.from('fb0c852e311e15047638f866c293ca47174bad1312592f7db6f9e0fd33503c81c1f948455441db0db6b6e9ef38723982bde482adc91d82eaeb3b8be722193ea3', 'hex'),
            },
        ];

        // Test signature verification with test vectors
        it('SM2Multikey signature test vectors', () => {
            for (const vector of testVectors) {
                const key = SM2Multikey.from(vector.key);

                // Test verification with test vector signature
                const { verify } = key.verifier();
                assert.strictEqual(verify({ data: vector.message, signature: vector.signature }), true, `${vector.name}: Should verify test vector signature`);

                // Test signing and verification
                const { sign } = key.signer();
                const newSignature = sign({ data: vector.message });
                assert.strictEqual(verify({ data: vector.message, signature: newSignature }), true, `${vector.name}: Should verify generated signature`);

                // Test verification with wrong message
                const wrongMessage = Buffer.from('wrong message');
                assert.strictEqual(verify({ data: wrongMessage, signature: vector.signature }), false, `${vector.name}: Should fail verification with wrong message`);
            }
        });

        // Test error cases
        it('SM2Multikey signature error cases', () => {
            const key = SM2Multikey.from(testVectors[0].key);

            // Test signing with invalid message
            const { sign } = key.signer();
            assert.throws(() => sign({ data: null }), { message: /data must be Buffer or Uint8Array/ });
            assert.throws(() => sign({ data: undefined }), { message: /data must be Buffer or Uint8Array/ });

            // Test verification with invalid signature
            const { verify } = key.verifier();
            assert.throws(() => verify({ data: Buffer.from('test'), signature: null }), { message: /signature must be Buffer or Uint8Array/ });
            assert.throws(() => verify({ data: Buffer.from('test'), signature: undefined }), { message: /signature must be Buffer or Uint8Array/ });
        });
    });

    describe('from and export', () => {
        it('should correctly import exported key with raw buffers', () => {
            // Generate a key pair
            const originalKey = SM2Multikey.generate();

            // Export with all options
            const exported = originalKey.export({
                publicKey: true,
                secretKey: true,
                includeContext: true,
                raw: true,
                canonicalize: true
            });

            // Import the exported key
            const importedKey = SM2Multikey.from(exported);

            // Test signing and verification
            const message = Buffer.from('test message');
            const signature = importedKey.signer().sign({ data: message });
            const valid = importedKey.verifier().verify({ data: message, signature });
            assert.strictEqual(valid, true);

            // Verify original key can verify signature from imported key
            const validCross = originalKey.verifier().verify({ data: message, signature });
            assert.strictEqual(validCross, true);
        });

        it('should handle Buffer data in exported key', () => {
            const key = SM2Multikey.generate();
            const exported = key.export({
                publicKey: true,
                secretKey: true,
                includeContext: true,
                raw: true
            });

            // Convert the exported key's Buffer data to hex strings
            const exportedHex = {
                ...exported,
                publicKey: exported.publicKey.toString('hex'),
                secretKey: exported.secretKey.toString('hex')
            };

            // Import using hex strings
            const importedFromHex = SM2Multikey.from({
                ...exportedHex,
                publicKey: Buffer.from(exportedHex.publicKey, 'hex'),
                secretKey: Buffer.from(exportedHex.secretKey, 'hex')
            });

            // Test signing and verification
            const message = Buffer.from('test message');
            const signature = importedFromHex.signer().sign({ data: message });
            const valid = importedFromHex.verifier().verify({ data: message, signature });
            assert.strictEqual(valid, true);
        });
    });
});
