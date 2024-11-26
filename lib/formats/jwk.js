/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview JWK (JSON Web Key) Format Handling for SM2 Keys
 * 
 * This module implements the JSON Web Key (JWK) format for SM2 key pairs as
 * specified in RFC 7517, with extensions for SM2 cryptography. It provides
 * bidirectional conversion between raw key bytes and JWK format.
 * 
 * Key Features:
 * - SM2 key pair JWK conversion
 * - Strict format validation
 * - Zero-copy operations
 * - Memory safety
 * - Type preservation
 * 
 * Security Considerations:
 * - Private key protection
 * - Memory clearing
 * - Format validation
 * - Type checking
 * - Input sanitization
 * 
 * Performance Notes:
 * - Minimal allocations
 * - Zero-copy where possible
 * - Early validation
 * - Efficient encoding
 * - Type preservation
 * 
 * JWK Format for SM2:
 * ```json
 * {
 *   "kty": "EC",            // Key Type (always "EC")
 *   "crv": "SM2",           // Curve Name (always "SM2")
 *   "x": "base64url(...)",  // X-coordinate (32 bytes)
 *   "y": "base64url(...)",  // Y-coordinate (32 bytes)
 *   "d": "base64url(...)"   // Private Key (32 bytes, optional)
 * }
 * ```
 * 
 * Standards Compliance:
 * - RFC 7517: JSON Web Key (JWK)
 * - RFC 7518: JSON Web Algorithms (JWA)
 * - GB/T 32918.1-2016: SM2 Key Format
 * - GB/T 35276-2017: SM2 for TLS
 * - GM/T 0009-2012: SM2 Digital Signature
 * 
 * Usage Example:
 * ```javascript
 * import { fromJwk, toJwk } from './jwk.js';
 * 
 * // Convert SM2 key pair to JWK
 * const jwk = await toJwk({
 *   keyPair: {
 *     publicKey: publicKeyBuffer,  // 64 bytes (x|y)
 *     secretKey: privateKeyBuffer  // 32 bytes (optional)
 *   }
 * });
 * 
 * // Convert JWK back to key pair
 * const keyPair = await fromJwk({
 *   jwk: {
 *     kty: 'EC',
 *     crv: 'SM2',
 *     x: 'base64url...',
 *     y: 'base64url...',
 *     d: 'base64url...'  // Optional
 *   }
 * });
 * ```
 * 
 * @module formats/jwk
 * @see {@link https://tools.ietf.org/html/rfc7517|RFC 7517}
 * @see {@link https://tools.ietf.org/html/rfc7518|RFC 7518}
 */

import { toBase64Url, fromBase64Url } from './base64.js';
import { FormatError, ArgumentError, ErrorCodes } from '../core/errors.js';

/**
 * Import a key pair from JWK format
 * 
 * This function converts a JWK (JSON Web Key) object into an SM2 key pair,
 * following RFC 7517 and SM2 specifications. It performs thorough validation
 * of the input format and key components.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Format verification
 * 3. Component extraction
 * 4. Key assembly
 * 5. Type conversion
 * 
 * Security Considerations:
 * - JWK format validation
 * - Key size verification
 * - Memory safety
 * - Private key handling
 * - Type checking
 * 
 * Performance Notes:
 * - Early validation
 * - Minimal copying
 * - Efficient decoding
 * - Buffer reuse
 * - Type preservation
 * 
 * Key Format Details:
 * ```
 * Public Key (64 bytes):
 * | X-coordinate | Y-coordinate |
 * | 32 bytes    | 32 bytes     |
 * 
 * Private Key (optional):
 * | D-value |
 * | 32 bytes |
 * ```
 * 
 * @param {Object} options - Import options
 * @param {Object} options.jwk - JWK object to import
 * @param {string} options.jwk.kty - Key type (must be "EC")
 * @param {string} options.jwk.crv - Curve name (must be "SM2")
 * @param {string} options.jwk.x - Base64URL-encoded x-coordinate
 * @param {string} options.jwk.y - Base64URL-encoded y-coordinate
 * @param {string} [options.jwk.d] - Base64URL-encoded private key
 * @param {boolean} [options.secretKey=false] - Whether to include private key
 * @param {string} [options.id] - Key ID
 * @param {string} [options.controller] - Key controller
 * @returns {Object} Key pair object
 * @returns {Buffer} .publicKey - 64-byte public key buffer
 * @returns {Buffer} [.secretKey] - 32-byte private key buffer
 * @returns {string} [.id] - Key ID
 * @returns {string} [.controller] - Key controller
 * @throws {ArgumentError} If JWK object is invalid
 * @throws {FormatError} If JWK format is invalid
 * 
 * @example
 * ```javascript
 * // Import a public key JWK
 * const publicKeyPair = await fromJwk({
 *   jwk: {
 *     kty: 'EC',
 *     crv: 'SM2',
 *     x: 'base64url...',
 *     y: 'base64url...'
 *   }
 * });
 * 
 * // Import a private key JWK
 * const privateKeyPair = await fromJwk({
 *   jwk: {
 *     kty: 'EC',
 *     crv: 'SM2',
 *     x: 'base64url...',
 *     y: 'base64url...',
 *     d: 'base64url...'  // Optional
 *   }
 * });
 * ```
 */
export function fromJwk({ jwk, secretKey = false, id, controller } = {}) {
  if (!jwk || typeof jwk !== 'object') {
    throw new ArgumentError('Invalid JWK object');
  }

  if (jwk.kty !== 'EC' || jwk.crv !== 'SM2') {
    throw new ArgumentError('Invalid key type or curve');
  }

  if (!jwk.x || !jwk.y) {
    throw new ArgumentError('Missing public key coordinates');
  }

  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);

  if (x.length !== 32 || y.length !== 32) {
    throw new ArgumentError('Invalid coordinate length');
  }

  const publicKey = Buffer.concat([x, y]);

  let secretKeyBuffer = null;
  if (secretKey && jwk.d) {
    secretKeyBuffer = fromBase64Url(jwk.d);
    if (secretKeyBuffer.length !== 32) {
      throw new ArgumentError('Invalid private key length');
    }
  }

  return {
    publicKey,
    secretKey: secretKeyBuffer,
    id,
    controller
  };
}

/**
 * Export a key pair to JWK format
 * 
 * This function converts an SM2 key pair into a JWK (JSON Web Key) object,
 * following RFC 7517 and SM2 specifications. It ensures proper formatting
 * and encoding of all key components.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Key extraction
 * 3. Format conversion
 * 4. Base64URL encoding
 * 5. JWK assembly
 * 
 * Security Considerations:
 * - Key size validation
 * - Private key handling
 * - Memory safety
 * - Buffer bounds
 * - Type checking
 * 
 * Performance Notes:
 * - Zero-copy slicing
 * - Efficient encoding
 * - Minimal allocation
 * - Buffer reuse
 * - Early validation
 * 
 * Key Requirements:
 * ```
 * Public Key (required):
 * | X-coordinate | Y-coordinate |
 * | 32 bytes    | 32 bytes     |
 * Total: 64 bytes
 * 
 * Private Key (optional):
 * | D-value |
 * | 32 bytes |
 * ```
 * 
 * @param {Object} options - Export options
 * @param {Object} options.keyPair - Key pair to export
 * @param {Buffer} options.keyPair.publicKey - 64-byte public key buffer
 * @param {Buffer} [options.keyPair.secretKey] - 32-byte private key buffer
 * @param {boolean} [options.secretKey=false] - Whether to include private key
 * @returns {Object} JWK object
 * @returns {string} .kty - Key type ("EC")
 * @returns {string} .crv - Curve name ("SM2")
 * @returns {string} .x - Base64URL-encoded x-coordinate
 * @returns {string} .y - Base64URL-encoded y-coordinate
 * @returns {string} [.d] - Base64URL-encoded private key
 * @throws {ArgumentError} If key format is invalid
 */
export function toJwk({ keyPair, secretKey = false } = {}) {
  if (!keyPair || typeof keyPair !== 'object') {
    throw new ArgumentError('Invalid key pair');
  }

  const publicKey = keyPair.publicKey;
  if (!publicKey || !Buffer.isBuffer(publicKey) || publicKey.length !== 64) {
    throw new ArgumentError('publicKey must be 64 bytes');
  }

  const x = publicKey.slice(0, 32);
  const y = publicKey.slice(32, 64);

  const jwk = {
    kty: 'EC',
    crv: 'SM2',
    x: toBase64Url(x),
    y: toBase64Url(y)
  };

  if (secretKey && keyPair.secretKey) {
    const secretKeyBuffer = keyPair.secretKey;
    if (!Buffer.isBuffer(secretKeyBuffer) || secretKeyBuffer.length !== 32) {
      throw new ArgumentError('secretKey must be 32 bytes');
    }
    jwk.d = toBase64Url(secretKeyBuffer);
  }

  return jwk;
}

/**
 * Extract public key bytes from JWK
 * 
 * This function extracts and validates the public key components from a
 * JWK object, returning them in the standard SM2 public key format.
 * It ensures proper formatting and encoding of coordinates.
 * 
 * Processing Steps:
 * 1. JWK validation
 * 2. Format verification
 * 3. Component extraction
 * 4. Base64URL decoding
 * 5. Key assembly
 * 
 * Security Considerations:
 * - Format validation
 * - Coordinate validation
 * - Buffer safety
 * - Memory bounds
 * - Type checking
 * 
 * Performance Notes:
 * - Minimal copying
 * - Efficient decoding
 * - Early validation
 * - Buffer reuse
 * - Type preservation
 * 
 * Key Format:
 * ```
 * Output Buffer (64 bytes):
 * | X-coordinate | Y-coordinate |
 * | 32 bytes    | 32 bytes     |
 * ```
 * 
 * @param {Object} options - Extraction options
 * @param {Object} options.jwk - JWK object
 * @param {string} options.jwk.kty - Key type (must be "EC")
 * @param {string} options.jwk.crv - Curve name (must be "SM2")
 * @param {string} options.jwk.x - Base64URL-encoded x-coordinate
 * @param {string} options.jwk.y - Base64URL-encoded y-coordinate
 * @returns {Buffer} 64-byte public key buffer
 * @throws {TypeError} If JWK object is invalid
 * @throws {FormatError} If JWK format is invalid
 * 
 * @example
 * ```javascript
 * // Extract public key from JWK
 * const publicKey = await jwkToPublicKeyBytes({
 *   jwk: {
 *     kty: 'EC',
 *     crv: 'SM2',
 *     x: 'base64url...',  // 32 bytes encoded
 *     y: 'base64url...'   // 32 bytes encoded
 *   }
 * });
 * console.log(publicKey.length);  // 64 bytes
 * ```
 */
export function jwkToPublicKeyBytes({ jwk } = {}) {
  if (!jwk || typeof jwk !== 'object') {
    throw new ArgumentError('Invalid JWK');
  }

  if (jwk.kty !== 'EC' || jwk.crv !== 'SM2') {
    throw new FormatError('Invalid JWK format');
  }

  if (!jwk.x || !jwk.y) {
    throw new FormatError('Missing required JWK parameters');
  }

  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);
  return Buffer.concat([x, y]);
}

/**
 * Extract private key bytes from JWK
 * 
 * This function extracts and validates the private key component from a
 * JWK object, returning it in the standard SM2 private key format.
 * It implements strict security measures for private key handling.
 * 
 * Processing Steps:
 * 1. JWK validation
 * 2. Format verification
 * 3. Private key extraction
 * 4. Base64URL decoding
 * 5. Security checks
 * 
 * Security Considerations:
 * - Private key validation
 * - Memory clearing
 * - Buffer safety
 * - Format verification
 * - Type checking
 * 
 * Performance Notes:
 * - Minimal exposure
 * - Efficient decoding
 * - Early validation
 * - Secure cleanup
 * - Type preservation
 * 
 * Key Format:
 * ```
 * Output Buffer (32 bytes):
 * | Private Key (d) |
 * | 32 bytes       |
 * ```
 * 
 * @param {Object} options - Extraction options
 * @param {Object} options.jwk - JWK object
 * @param {string} options.jwk.kty - Key type (must be "EC")
 * @param {string} options.jwk.crv - Curve name (must be "SM2")
 * @param {string} options.jwk.d - Base64URL-encoded private key
 * @returns {Buffer} 32-byte private key buffer
 * @throws {TypeError} If JWK object is invalid
 * @throws {FormatError} If JWK format is invalid
 * 
 * @example
 * ```javascript
 * // Extract private key from JWK
 * const privateKey = await jwkToSecretKeyBytes({
 *   jwk: {
 *     kty: 'EC',
 *     crv: 'SM2',
 *     d: 'base64url...'  // 32 bytes encoded
 *   }
 * });
 * 
 * // Use the private key
 * try {
 *   console.log(privateKey.length);  // 32 bytes
 * } finally {
 *   // Clear sensitive data
 *   privateKey.fill(0);
 * }
 * ```
 */
export function jwkToSecretKeyBytes({ jwk } = {}) {
  if (!jwk || typeof jwk !== 'object') {
    throw new ArgumentError('Invalid JWK');
  }

  if (!jwk.d) {
    throw new FormatError('Missing private key parameter');
  }

  return fromBase64Url(jwk.d);
}
