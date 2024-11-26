/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SM2Multikey } from './config.js';

describe('SM2 Multicodec Headers', () => {
  // Test vectors
  const TEST_VECTORS = {
    // Test key pair
    keyPair: {
      // Uncompressed public key (64 bytes, without 0x04 prefix)
      publicKey: Buffer.from('d03b573a12baa0614b004eb17a3683953ac1d45c2a0c8cff55a8dc44c8a6b8d5ec049779a94a305571b852a91300d36612279f4bae0039201f5335625386ecc4', 'hex'),
      // Private key (32 bytes)
      secretKey: Buffer.from('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'hex')
    },
    // Expected encoding results
    encoded: {
      // Multibase encoding of compressed public key (with multicodec header)
      publicKeyMultibase: 'zEPJcCQ4kKGebz5ombkjw9mgikPckWeYDLhvZBzPckNsfjBa4',
      // Multibase encoding of private key (with multicodec header)
      secretKeyMultibase: 'z44CBRpqNAzcr3pqMGMGNTiYpw4hFpSq74Zg32mQyKh2JXiv'
    }
  };

  it('should encode SM2 public key with correct format', () => {
    // Generate a new key pair
    const keyPair = SM2Multikey.generate();

    // Export public key
    const exported = keyPair.export({ publicKey: true, secretKey: false });
    const publicKeyMultibase = exported.publicKeyMultibase;

    // Verify multibase encoding format
    assert.strictEqual(publicKeyMultibase[0], 'z', 'Public key should use base58btc encoding');
    
    // Import the exported key to verify format
    const importedKey = SM2Multikey.from({
      type: 'Multikey',
      publicKeyMultibase
    });
    
    // Verify the imported key matches original
    assert.deepStrictEqual(importedKey.publicKey, keyPair.publicKey);
  });

  it('should encode SM2 private key with correct format', () => {
    // Generate a new key pair
    const keyPair = SM2Multikey.generate();

    // Export private key
    const exported = keyPair.export({ publicKey: false, secretKey: true });
    const secretKeyMultibase = exported.secretKeyMultibase;

    // Verify multibase encoding format
    assert.strictEqual(secretKeyMultibase[0], 'z', 'Private key should use base58btc encoding');
    
    // Import the exported key to verify format
    const importedKey = SM2Multikey.from({
      type: 'Multikey',
      publicKeyMultibase: keyPair.export({ publicKey: true, secretKey: false }).publicKeyMultibase,
      secretKeyMultibase
    });
    
    // Verify the imported key matches original
    assert.deepStrictEqual(importedKey.secretKey, keyPair.secretKey);
  });

  it('should decode fixed SM2 key pair correctly', () => {
    // Import public key
    const importedPublic = SM2Multikey.from({
      type: 'Multikey',
      publicKeyMultibase: TEST_VECTORS.encoded.publicKeyMultibase
    });

    // Verify imported public key matches test vector
    assert.deepStrictEqual(
      importedPublic.publicKey,
      TEST_VECTORS.keyPair.publicKey,
      'Decoded public key mismatch'
    );

    // Import private key
    const importedPrivate = SM2Multikey.from({
      type: 'Multikey',
      publicKeyMultibase: TEST_VECTORS.encoded.publicKeyMultibase,
      secretKeyMultibase: TEST_VECTORS.encoded.secretKeyMultibase
    });

    // Verify imported private key matches test vector
    assert.deepStrictEqual(
      importedPrivate.secretKey,
      TEST_VECTORS.keyPair.secretKey,
      'Decoded private key mismatch'
    );
  });
});
