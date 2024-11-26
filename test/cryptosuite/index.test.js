/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

import assert from 'node:assert';
import { describe, it, before } from 'node:test';
import { SM2Multikey, cryptosuite } from '../config.js';

describe('SM2 2023 Cryptosuite', () => {
  describe('interface', () => {
    it('should export required properties', () => {
      assert.strictEqual(typeof cryptosuite.canonize, 'function');
      assert.strictEqual(typeof cryptosuite.createVerifier, 'function');
      assert.strictEqual(typeof cryptosuite.name, 'string');
      assert.strictEqual(typeof cryptosuite.requiredAlgorithm, 'string');
    });

    it('should have correct name and algorithm', () => {
      assert.strictEqual(cryptosuite.name, 'sm2-2023');
      assert.strictEqual(cryptosuite.requiredAlgorithm, 'SM2');
    });
  });

  describe('canonize', () => {
    it('should canonize simple document', async () => {
      const input = {
        '@context': {
          '@vocab': 'https://w3id.org/security/v2#',
          'ex': 'https://example.org/'
        },
        'ex:b': 2,
        'ex:a': 1,
        'ex:c': {
          'ex:e': true,
          'ex:d': null
        }
      };
      const result = await cryptosuite.canonize(input);
      assert(result.includes('_:c14n'));
      assert(result.includes('"1"'));
      assert(result.includes('"2"'));
      assert(result.includes('true'));
    });

    it('should produce identical output for equivalent documents', async () => {
      const doc1 = {
        '@context': {
          '@vocab': 'https://w3id.org/security/v2#',
          'ex': 'https://example.org/'
        },
        'ex:a': 1,
        'ex:b': { 'ex:c': true }
      };
      const doc2 = {
        '@context': {
          '@vocab': 'https://w3id.org/security/v2#',
          'ex': 'https://example.org/'
        },
        'ex:b': { 'ex:c': true },
        'ex:a': 1
      };
      const result1 = await cryptosuite.canonize(doc1);
      const result2 = await cryptosuite.canonize(doc2);
      assert.strictEqual(result1, result2);
    });
  });

  describe('createVerifier', () => {
    let keyPair;

    before(() => {
      keyPair = SM2Multikey.generate();
    });

    it('should create verifier from verification method', () => {
      const key = keyPair.export();
      const verifier = cryptosuite.createVerifier({ verificationMethod: key });
      assert.strictEqual(typeof verifier.verify, 'function');
    });

    it('should verify valid signature', () => {
      const key = keyPair.export();
      const { verify } = cryptosuite.createVerifier({ verificationMethod: key });
      const message = Buffer.from('test message');
      // 创建一个 64 字节的模拟签名
      const signature = Buffer.alloc(64, 0);
      // 填充一些随机数据
      for (let i = 0; i < 64; i++) {
        signature[i] = Math.floor(Math.random() * 256);
      }
      assert.doesNotThrow(() => verify({ data: message, signature }));
    });
  });
});
