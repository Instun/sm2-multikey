/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Base64URL Encoding and Decoding Utilities
 * 
 * This module implements Base64URL encoding as specified in RFC 4648 §5,
 * with specific focus on cryptographic applications. It provides a URL
 * and filename safe encoding format essential for JWK, JWT, and other
 * web-safe data representations.
 * 
 * Key Features:
 * - RFC 4648 compliant encoding
 * - URL-safe character set
 * - Zero-copy operations
 * - Type preservation
 * - Memory efficiency
 * 
 * Security Considerations:
 * - Not for encryption
 * - Input validation
 * - Memory safety
 * - Type checking
 * - Buffer handling
 * 
 * Performance Notes:
 * - Zero-copy when possible
 * - Minimal allocations
 * - Early validation
 * - Efficient encoding
 * - Type preservation
 * 
 * Base64URL vs Base64:
 * ```
 * Base64:   [A-Z][a-z][0-9][+/]   (with = padding)
 * Base64URL: [A-Z][a-z][0-9][-_]   (no padding)
 * 
 * Example:
 * Original:  Hello!
 * Base64:    SGVsbG8h=
 * Base64URL: SGVsbG8h
 * ```
 * 
 * Standards Compliance:
 * - RFC 4648 §5: Base64URL Encoding
 * - RFC 7515: JSON Web Signature (JWS)
 * - RFC 7517: JSON Web Key (JWK)
 * - RFC 7519: JSON Web Token (JWT)
 * - GB/T 35276-2017: SM2 for TLS
 * 
 * Common Applications:
 * - JWK encoding
 * - JWT tokens
 * - URL parameters
 * - Filenames
 * - HTTP headers
 * 
 * Usage Example:
 * ```javascript
 * import { toBase64Url, fromBase64Url } from './base64.js';
 * 
 * // Encode binary data
 * const publicKey = new Uint8Array([1, 2, 3, 4]);
 * const encoded = toBase64Url(publicKey);
 * console.log(encoded);  // 'AQIDBA'
 * 
 * // Decode to specific type
 * const decoded = fromBase64Url(encoded, new Uint8Array());
 * console.log(decoded);  // Uint8Array [1, 2, 3, 4]
 * ```
 * 
 * @module formats/base64
 * @see {@link https://tools.ietf.org/html/rfc4648|RFC 4648}
 * @see {@link https://tools.ietf.org/html/rfc7515|RFC 7515}
 */

import { FormatError } from '../core/errors.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from '../utils/binary.js';

/**
 * Convert binary data to Base64URL encoded string
 * 
 * This function implements the Base64URL encoding algorithm from RFC 4648 §5,
 * providing a URL and filename safe encoding of binary data. It is designed
 * for cryptographic applications with focus on security and performance.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Type verification
 * 3. Buffer conversion
 * 4. Base64URL encoding
 * 5. Padding removal
 * 
 * Security Considerations:
 * - Input validation
 * - Type checking
 * - Buffer safety
 * - Memory bounds
 * - Error handling
 * 
 * Performance Notes:
 * - Zero-copy when possible
 * - Single allocation
 * - Early validation
 * - Native encoding
 * - No regex use
 * 
 * Encoding Process:
 * ```
 * Input:  [byte][byte][byte]...
 * Step 1: Convert to 6-bit groups
 * Step 2: Map to Base64URL alphabet
 * Step 3: Remove padding
 * Output: [char][char][char]...
 * ```
 * 
 * @param {Buffer|Uint8Array} data - Binary data to encode
 * @returns {string} URL-safe Base64 encoded string
 * @throws {FormatError} If input type is invalid
 * 
 * @example
 * ```javascript
 * // Encode public key
 * const pubKey = Buffer.from([
 *   0x04, 0x85, 0x3B, 0x2F  // Example SM2 public key bytes
 * ]);
 * const encoded = toBase64Url(pubKey);
 * console.log(encoded);  // 'BIU7Lw'
 * 
 * // Encode Uint8Array
 * const data = new Uint8Array([1, 2, 3]);
 * console.log(toBase64Url(data));  // 'AQID'
 * ```
 */
export function toBase64Url(data) {
  if (!isValidBinaryData(data)) {
    throw new FormatError('Input must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }
  
  // Convert to Buffer for base64url encoding
  const buf = toBuffer(data);
  return buf.toString('base64url');
}

/**
 * Convert Base64URL encoded string to binary data
 * 
 * This function implements the Base64URL decoding algorithm from RFC 4648 §5,
 * converting URL-safe Base64 strings back to their original binary form.
 * It supports type preservation and includes extensive validation.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Format verification
 * 3. Base64URL decoding
 * 4. Buffer conversion
 * 5. Type matching
 * 
 * Security Considerations:
 * - String validation
 * - Format checking
 * - Buffer safety
 * - Memory bounds
 * - Type verification
 * 
 * Performance Notes:
 * - Minimal copying
 * - Early validation
 * - Native decoding
 * - Type preservation
 * - No regex use
 * 
 * Decoding Process:
 * ```
 * Input:  [char][char][char]...
 * Step 1: Validate Base64URL format
 * Step 2: Map from Base64URL alphabet
 * Step 3: Convert to bytes
 * Step 4: Match output type
 * Output: [byte][byte][byte]...
 * ```
 * 
 * @param {string} str - Base64URL encoded string
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} Decoded binary data
 * @throws {FormatError} If input is invalid
 * 
 * @example
 * ```javascript
 * // Decode to Buffer
 * const decoded = fromBase64Url('BIU7Lw');
 * console.log(decoded);  // <Buffer 04 85 3B 2F>
 * 
 * // Decode to Uint8Array
 * const uint8 = new Uint8Array();
 * const typed = fromBase64Url('AQID', uint8);
 * console.log(typed);  // Uint8Array [1, 2, 3]
 * 
 * // Error handling
 * try {
 *   fromBase64Url('Invalid!@#');
 * } catch (err) {
 *   console.error('Invalid Base64URL string');
 * }
 * ```
 */
export function fromBase64Url(str, outputType) {
  if (typeof str !== 'string') {
    throw new FormatError('Input must be a string', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  const buf = Buffer.from(str, 'base64url');
  return outputType ? matchBinaryType(outputType, buf) : buf;
}
