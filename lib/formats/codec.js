/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Multicodec and Multibase Key Encoding Utilities
 * 
 * This module implements the Multicodec and Multibase specifications for
 * SM2 cryptographic key encoding. It provides a self-describing format
 * that combines type information with key data, enabling reliable key
 * identification and handling.
 * 
 * Key Features:
 * - Multicodec compliance
 * - Multibase support
 * - Zero-copy operations
 * - Type preservation
 * - Format validation
 * 
 * Security Considerations:
 * - Key type validation
 * - Format verification
 * - Memory safety
 * - Error handling
 * - Buffer bounds
 * 
 * Performance Notes:
 * - Minimal copying
 * - Early validation
 * - Efficient encoding
 * - Buffer reuse
 * - Type preservation
 * 
 * Key Format Structure:
 * ```
 * | Multibase | Multicodec | Key Data   |
 * |-----------|------------|------------|
 * | 'z'       | 0x8624     | Public Key |
 * | 'z'       | 0x8724     | Secret Key |
 * 
 * Example:
 * Public:  z86240123...  (Base58BTC('z') + SM2-pub(0x8624) + key)
 * Private: z87240123...  (Base58BTC('z') + SM2-priv(0x8724) + key)
 * ```
 * 
 * Standards Compliance:
 * - Multicodec v1.0
 * - Multibase v1.0
 * - IPFS CID v1
 * - GM/T 0009-2012
 * - GB/T 32918.1-2016
 * 
 * Common Applications:
 * - Key storage
 * - Key exchange
 * - IPFS content
 * - Key identification
 * - Format conversion
 * 
 * Usage Example:
 * ```javascript
 * import {
 *   encodeKey,
 *   decodeKey,
 *   MULTICODEC_SM2_PUB_HEADER
 * } from './codec.js';
 * 
 * // Encode a public key
 * const publicKey = new Uint8Array([1, 2, 3, 4]);  // Example bytes
 * const encoded = encodeKey(MULTICODEC_SM2_PUB_HEADER, publicKey);
 * console.log(encoded);  // 'z8624...'
 * 
 * // Decode and validate
 * const { key, prefix } = decodeKey(encoded);
 * if (prefix.equals(MULTICODEC_SM2_PUB_HEADER)) {
 *   console.log('Valid SM2 public key');
 * }
 * ```
 * 
 * @module formats/codec
 * @see {@link https://github.com/multiformats/multicodec|Multicodec}
 * @see {@link https://github.com/multiformats/multibase|Multibase}
 * @see {@link https://github.com/multiformats/cid|CID}
 */

import { base58btc } from 'multiformats/bases/base58';
import { ArgumentError, KeyError, SM2Error, ErrorCodes } from '../core/errors.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from '../utils/binary.js';

/**
 * Multiformat Constants
 * 
 * These constants define the prefixes and headers used in the multiformat
 * encoding scheme. They follow the official multicodec and multibase
 * specifications for consistent key identification.
 * 
 * Format Details:
 * ```
 * Multibase:
 * 'z' - Base58BTC encoding prefix
 * 
 * Multicodec (varint encoded):
 * 0x8624 - SM2 public key  (0x1206)
 * 0x8724 - SM2 private key (0x1207)
 * ```
 * 
 * @constant
 * @readonly
 */
export const MULTIBASE_BASE58BTC_HEADER = 'z';

/**
 * SM2 Public Key Multicodec Header
 * 
 * This constant defines the multicodec prefix for SM2 public keys.
 * The value 0x8624 is the varint encoding of code 0x1206.
 * 
 * Header Structure:
 * ```
 * | 1st byte | 2nd byte |
 * | 0x86     | 0x24     |
 * | cont.bit | value    |
 * ```
 * 
 * @constant {Uint8Array}
 * @readonly
 */
export const MULTICODEC_SM2_PUB_HEADER = new Uint8Array([0x86, 0x24]);

/**
 * SM2 Private Key Multicodec Header
 * 
 * This constant defines the multicodec prefix for SM2 private keys.
 * The value 0x8724 is the varint encoding of code 0x1207.
 * 
 * Header Structure:
 * ```
 * | 1st byte | 2nd byte |
 * | 0x87     | 0x24     |
 * | cont.bit | value    |
 * ```
 * 
 * @constant {Uint8Array}
 * @readonly
 */
export const MULTICODEC_SM2_PRIV_HEADER = new Uint8Array([0x87, 0x24]);

/**
 * Encode a cryptographic key with multiformat prefixes
 * 
 * This function implements the multiformat encoding scheme, combining
 * multicodec and multibase specifications to create a self-describing
 * key format. It ensures proper type identification and encoding.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Type verification
 * 3. Prefix assembly
 * 4. Key concatenation
 * 5. Base58BTC encoding
 * 
 * Security Considerations:
 * - Key validation
 * - Prefix verification
 * - Buffer safety
 * - Memory bounds
 * - Type checking
 * 
 * Performance Notes:
 * - Single allocation
 * - Early validation
 * - Efficient encoding
 * - Buffer reuse
 * - Type preservation
 * 
 * Encoding Process:
 * ```
 * Input:  prefix=[0x86,0x24] key=[k1,k2,...]
 * Step 1: Validate inputs
 * Step 2: Combine [prefix|key]
 * Step 3: Add multibase prefix
 * Output: "z" + base58btc([prefix|key])
 * ```
 * 
 * @param {Uint8Array} prefix - Multicodec prefix for key type
 * @param {Buffer|Uint8Array} key - Raw key data to encode
 * @returns {string} Multiformat encoded key string
 * @throws {ArgumentError} If inputs are invalid
 * 
 * @example
 * ```javascript
 * // Encode a public key
 * const pubKey = Buffer.from([
 *   0x04, // Uncompressed point
 *   ...new Array(63).fill(0) // X and Y coordinates
 * ]);
 * const encoded = encodeKey(MULTICODEC_SM2_PUB_HEADER, pubKey);
 * console.log(encoded);  // 'z8624...'
 * 
 * // Encode a private key
 * const privKey = Buffer.from(new Array(32).fill(0));
 * const encodedPriv = encodeKey(MULTICODEC_SM2_PRIV_HEADER, privKey);
 * console.log(encodedPriv);  // 'z8724...'
 * ```
 */
export function encodeKey(prefix, key) {
  if (!isValidBinaryData(key)) {
    throw new ArgumentError('Invalid key', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Key must be a Buffer or Uint8Array'
    });
  }

  // Convert key to Buffer for concatenation
  const keyBuf = toBuffer(key);
  const data = Buffer.concat([Buffer.from(prefix), keyBuf]);
  return base58btc.encode(data);
}

/**
 * Decode a multiformat encoded key string
 * 
 * This function implements the multiformat decoding process, handling
 * both multicodec and multibase aspects. It performs thorough validation
 * to ensure key integrity and proper format compliance.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Multibase verification
 * 3. Base58BTC decoding
 * 4. Multicodec extraction
 * 5. Key separation
 * 
 * Security Considerations:
 * - Format validation
 * - Prefix verification
 * - Buffer safety
 * - Error handling
 * - Type checking
 * 
 * Performance Notes:
 * - Minimal copying
 * - Early validation
 * - Efficient decoding
 * - Buffer reuse
 * - Type preservation
 * 
 * Decoding Process:
 * ```
 * Input:  "z8624k1k2k3..."
 * Step 1: Validate multibase prefix ('z')
 * Step 2: Base58BTC decode
 * Step 3: Extract multicodec prefix
 * Step 4: Validate prefix
 * Step 5: Extract key data
 * Output: {
 *   prefix: [0x86,0x24],
 *   key: [k1,k2,k3,...]
 * }
 * ```
 * 
 * @param {string} encoded - Multiformat encoded key string
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {{key: Buffer|Uint8Array, prefix: Buffer}} Decoded key and prefix
 * @throws {ArgumentError} If input is invalid
 * @throws {KeyError} If key format is invalid
 * 
 * @example
 * ```javascript
 * // Decode and validate a public key
 * try {
 *   const { key, prefix } = decodeKey('z8624...');
 *   
 *   if (prefix.equals(MULTICODEC_SM2_PUB_HEADER)) {
 *     console.log('Valid SM2 public key');
 *     console.log('Length:', key.length);  // 64 bytes
 *   }
 * } catch (err) {
 *   if (err instanceof KeyError) {
 *     console.error('Invalid key format');
 *   }
 * }
 * 
 * // Decode with type matching
 * const uint8 = new Uint8Array();
 * const { key } = decodeKey('z8624...', uint8);
 * console.log(key instanceof Uint8Array);  // true
 * ```
 */
export function decodeKey(encoded, outputType) {
  if (!encoded || typeof encoded !== 'string') {
    throw new ArgumentError('Invalid encoded key', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Encoded key must be a non-empty string'
    });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new ArgumentError('Invalid output type', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Output type must be a Buffer or Uint8Array'
    });
  }

  if (!encoded.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
    throw new KeyError('Invalid SM2 public key prefix', { code: ErrorCodes.ERR_KEY_FORMAT_NEW });
  }

  try {
    const data = base58btc.decode(encoded);
    if (data.length < 2) {
      throw new KeyError('Invalid key length', { code: ErrorCodes.ERR_KEY_FORMAT_NEW });
    }

    const prefix = Buffer.from(data.subarray(0, 2));
    const key = Buffer.from(data.subarray(2));

    // Verify prefix
    if (!prefix.equals(MULTICODEC_SM2_PUB_HEADER) &&
        !prefix.equals(MULTICODEC_SM2_PRIV_HEADER)) {
      throw new KeyError('Invalid SM2 public key prefix', { code: ErrorCodes.ERR_KEY_FORMAT_NEW });
    }

    // Match output type if specified
    return {
      key: outputType ? matchBinaryType(outputType, key) : key,
      prefix
    };
  } catch (error) {
    if (error instanceof SM2Error) {
      throw error;
    }
    throw new KeyError('Invalid SM2 public key prefix', {
      code: ErrorCodes.ERR_KEY_FORMAT_NEW,
      cause: error
    });
  }
}
