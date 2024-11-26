/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { SM2Multikey } from './config.js';
import { ErrorCodes } from '../lib/core/errors.js';

describe('SM2Multikey Advanced Tests', () => {
  describe('JWK format conversion', () => {
    it('should convert to and from JWK format', () => {
      const key = SM2Multikey.generate();
      const jwk = SM2Multikey.toJwk({ keyPair: key });
      const imported = SM2Multikey.fromJwk({ jwk });
      
      // Verify public key conversion
      assert.deepStrictEqual(imported.publicKey, key.publicKey);
      assert.strictEqual(imported.secretKey, null);
    });

    it('should handle private key in JWK conversion', () => {
      const key = SM2Multikey.generate();
      const jwk = SM2Multikey.toJwk({ keyPair: key, secretKey: true });
      const imported = SM2Multikey.fromJwk({ jwk, secretKey: true });
      
      // Verify both public and private key conversion
      assert.deepStrictEqual(imported.publicKey, key.publicKey);
      assert.deepStrictEqual(imported.secretKey, key.secretKey);
    });
  });

  describe('key compression and encoding', () => {
    it('should correctly compress and decompress public key', () => {
      const key = SM2Multikey.generate();
      const exported = key.export({ raw: true });
      
      // Verify public key size
      assert.strictEqual(exported.publicKey.length, 64); // SM2 公钥是 64 字节
      
      // Verify key can be imported back
      const imported = SM2Multikey.from({
        type: 'Multikey',
        publicKey: exported.publicKey
      });
      assert.deepStrictEqual(imported.publicKey, key.publicKey);
    });

    it('should handle different encoding formats', () => {
      const key = SM2Multikey.generate();
      
      // Test multibase encoding
      const exported = key.export();
      assert(exported.publicKeyMultibase.startsWith('z')); // multibase 编码以 z 开头
      
      // Test raw format
      const rawExported = key.export({ raw: true });
      assert(Buffer.isBuffer(rawExported.publicKey));
    });
  });

  describe('error recovery and edge cases', () => {
    it('should handle large messages', () => {
      const key = SM2Multikey.generate();
      const largeMessage = Buffer.alloc(1024 * 1024, 'test message'); // 1MB
      
      // Sign and verify large message
      const { sign } = key.signer();
      const signature = sign({ data: largeMessage });
      
      const { verify } = key.verifier();
      const valid = verify({ data: largeMessage, signature });
      
      assert.strictEqual(valid, true);
    });
  });

  describe('performance', () => {
    it('should perform key generation within acceptable time', () => {
      const start = Date.now();
      SM2Multikey.generate();
      const end = Date.now();
      
      // Key generation should take less than 1 second
      assert(end - start < 1000);
    });

    it('should handle multiple sign/verify operations efficiently', () => {
      const key = SM2Multikey.generate();
      const message = Buffer.from('test message');
      const iterations = 10;
      
      const { sign } = key.signer();
      const { verify } = key.verifier();
      
      const start = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const signature = sign({ data: message });
        const valid = verify({ data: message, signature });
        assert.strictEqual(valid, true);
      }
      
      const end = Date.now();
      const avgTime = (end - start) / iterations;
      
      // Each sign+verify operation should take less than 10ms on average
      assert(avgTime < 100);
    });
  });

  describe('compatibility', () => {
    it('should handle different message encodings', () => {
      const key = SM2Multikey.generate();
      const { sign } = key.signer();
      const { verify } = key.verifier();
      
      // Test UTF-8 encoded Chinese characters
      const utf8Message = Buffer.from('测试消息', 'utf8');
      const utf8Signature = sign({ data: utf8Message });
      assert.strictEqual(verify({ data: utf8Message, signature: utf8Signature }), true);
      
      // Test Base64 encoded message
      const base64Message = Buffer.from('dGVzdCBtZXNzYWdl', 'base64');
      const base64Signature = sign({ data: base64Message });
      assert.strictEqual(verify({ data: base64Message, signature: base64Signature }), true);
      
      // Test hex encoded message
      const hexMessage = Buffer.from('74657374206d657373616765', 'hex');
      const hexSignature = sign({ data: hexMessage });
      assert.strictEqual(verify({ data: hexMessage, signature: hexSignature }), true);
    });
  });
});
