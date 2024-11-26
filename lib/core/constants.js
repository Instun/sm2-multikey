/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Core Constants for SM2 Cryptographic Operations
 * 
 * This module defines the core constants used throughout the SM2 cryptographic
 * implementation. It includes algorithm identifiers, key formats, curve
 * parameters, and usage flags.
 * 
 * Constants Categories:
 * - Algorithm identifiers
 * - Key type definitions
 * - Context URLs
 * - Multiformat prefixes
 * - Curve parameters
 * - Usage flags
 * 
 * Standards Compliance:
 * - GB/T 32918.1-2016: SM2 Parameters
 * - Multicodec v1.0: Key Prefixes
 * - Multibase v1.0: Encodings
 * - W3C Security Vocabulary
 * - IETF RFC 8410
 * 
 * Usage Example:
 * ```javascript
 * import {
 *   ALGORITHM,
 *   SM2_CURVE,
 *   KEY_USAGE
 * } from './core/constants.js';
 * 
 * // Algorithm identification
 * console.log(ALGORITHM);  // 'SM2'
 * 
 * // Curve parameters
 * console.log(SM2_CURVE.P);  // Prime modulus
 * 
 * // Key usage flags
 * console.log(KEY_USAGE.SIGN);  // 'sign'
 * ```
 * 
 * @module core/constants
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 * @see {@link https://w3c-ccg.github.io/security-vocab/|Security Vocabulary}
 */

/**
 * Algorithm Name
 * 
 * Identifies the cryptographic algorithm as SM2. This constant is used
 * in key formats, JWK headers, and algorithm identifiers.
 * 
 * Usage:
 * - JWK 'alg' header
 * - Key type identification
 * - Algorithm selection
 * 
 * @constant {string}
 * @default 'SM2'
 */
export const ALGORITHM = 'SM2';

/**
 * Key Extractability Flag
 * 
 * Determines whether private key material can be exported. This affects
 * key pair generation and import/export operations.
 * 
 * Security Impact:
 * - Controls key material access
 * - Affects key backup/restore
 * - Influences key management
 * 
 * @constant {boolean}
 * @default true
 */
export const EXTRACTABLE = true;

/**
 * SM2 Suite Context URL
 * 
 * W3C DID context URL for SM2 cryptographic suite version 1.
 * Used in verifiable credentials and DID documents.
 * 
 * URL Components:
 * - Base: w3id.org/security
 * - Suite: sm2-2023
 * - Version: v1
 * 
 * @constant {string}
 * @see {@link https://w3c-ccg.github.io/security-vocab/|Security Vocabulary}
 */
export const SM2_SUITE_CONTEXT_V1_URL =
  'https://w3id.org/security/suites/sm2-2023/v1';

/**
 * Multikey Context URL
 * 
 * W3C DID context URL for Multikey cryptographic suite version 1.
 * Used for key representation in DID documents.
 * 
 * URL Components:
 * - Base: w3id.org/security
 * - Suite: multikey
 * - Version: v1
 * 
 * @constant {string}
 * @see {@link https://w3c-ccg.github.io/security-vocab/|Security Vocabulary}
 */
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';

/**
 * Base58BTC Multibase Prefix
 * 
 * Multibase prefix for Base58BTC encoding. Used in key and signature
 * format encoding.
 * 
 * Format Details:
 * - Character: 'z'
 * - Encoding: Base58BTC
 * - Standard: Multibase v1.0
 * 
 * @constant {string}
 * @see {@link https://github.com/multiformats/multibase|Multibase}
 */
export const MULTIBASE_BASE58BTC_HEADER = 'z';

/**
 * SM2 Public Key Multicodec Header
 * 
 * Multicodec header for SM2 public keys. The value is the varint
 * encoding of the code point.
 * 
 * Format Details:
 * ```
 * Code: 0x1205 (SM2 public key)
 * Varint: 0x8524 (two bytes)
 * Bytes: [0x85, 0x24]
 * ```
 * 
 * @constant {Uint8Array}
 * @see {@link https://github.com/multiformats/multicodec|Multicodec}
 */
export const MULTICODEC_SM2_PUB_HEADER = new Uint8Array([0x85, 0x24]);

/**
 * SM2 Private Key Multicodec Header
 * 
 * Multicodec header for SM2 private keys. The value is the varint
 * encoding of the code point.
 * 
 * Format Details:
 * ```
 * Code: 0x1309 (SM2 private key)
 * Varint: 0x8926 (two bytes)
 * Bytes: [0x89, 0x26]
 * ```
 * 
 * @constant {Uint8Array}
 * @see {@link https://github.com/multiformats/multicodec|Multicodec}
 */
export const MULTICODEC_SM2_PRIV_HEADER = new Uint8Array([0x89, 0x26]);

/**
 * SM2 Elliptic Curve Parameters
 * 
 * Domain parameters for the SM2 elliptic curve as specified in
 * GB/T 32918.1-2016. All values are in hexadecimal.
 * 
 * Parameters:
 * ```
 * Prime Field:
 * P = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * 
 * Curve Equation: y^2 = x^3 + ax + b
 * A = -3 mod P
 * B = 0x28E9FA9E...
 * 
 * Group Order:
 * N = Order of base point G
 * 
 * Base Point:
 * G = (GX, GY) where
 * GX = 0x32C4AE2C...
 * GY = 0xBC3736A2...
 * ```
 * 
 * Security Properties:
 * - Field size: 256 bits
 * - Group order: Prime
 * - Cofactor: 1
 * - Security level: 128 bits
 * 
 * @constant {Object}
 * @property {string} P - Prime field modulus
 * @property {string} A - Curve coefficient A
 * @property {string} B - Curve coefficient B
 * @property {string} N - Group order
 * @property {string} GX - Base point X coordinate
 * @property {string} GY - Base point Y coordinate
 * 
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 */
export const SM2_CURVE = {
  // Prime field modulus
  P: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
  // Curve coefficient A
  A: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
  // Curve coefficient B
  B: '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
  // Group order
  N: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
  // Base point X coordinate
  GX: '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
  // Base point Y coordinate
  GY: 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
};

/**
 * SM2 Hash Algorithm
 * 
 * Identifier for the SM3 hash algorithm used with SM2 signatures.
 * SM3 is a cryptographic hash function that produces a 256-bit hash.
 * 
 * Algorithm Details:
 * - Output size: 256 bits
 * - Block size: 512 bits
 * - Word size: 32 bits
 * - Rounds: 64
 * 
 * @constant {string}
 * @default 'SM3'
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108015408199368.html|GB/T 32905}
 */
export const SM2_HASH = 'SM3';

/**
 * Key Usage Flags
 * 
 * Defines the allowed operations for SM2 keys. These flags control
 * key usage in cryptographic operations.
 * 
 * Usage Flags:
 * ```
 * SIGN: Key can be used for signing
 * VERIFY: Key can be used for verification
 * ```
 * 
 * Security Impact:
 * - Operation control
 * - Key separation
 * - Usage enforcement
 * 
 * @constant {Object}
 * @property {string} SIGN - Signing operation flag
 * @property {string} VERIFY - Verification operation flag
 */
export const KEY_USAGE = {
  SIGN: 'sign',
  VERIFY: 'verify'
};
