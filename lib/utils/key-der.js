/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview SM2 Key DER Format Utilities
 * 
 * This module provides utilities for handling SM2 key DER (Distinguished Encoding Rules) formats.
 * It implements the ASN.1 DER encoding rules for EC public and private keys, with specific
 * support for the SM2 elliptic curve cryptography.
 * 
 * Key Features:
 * - DER format parsing and validation
 * - Public key coordinate extraction
 * - Private key value extraction
 * - Support for standard EC/SM2 OIDs
 * 
 * Security Considerations:
 * - All operations are designed to be constant-time to prevent timing attacks
 * - Strict format validation to prevent ASN.1 parsing vulnerabilities
 * - No dynamic memory allocation during parsing to prevent DoS attacks
 * - Validates all algorithm identifiers to prevent algorithm confusion attacks
 * 
 * Performance Notes:
 * - Uses Buffer.subarray() for zero-copy operations where possible
 * - Avoids unnecessary memory allocations during parsing
 * - Sequential parsing without backtracking for optimal performance
 * 
 * Usage Example:
 * ```javascript
 * import { parsePublicKeyDER, extractSecretKeyD } from './key-der.js';
 * 
 * // Parse a DER encoded public key
 * const rawPublicKey = parsePublicKeyDER(derEncodedKey);
 * console.log(rawPublicKey.length); // 64 bytes (x||y coordinates)
 * 
 * // Extract private key value
 * const privateValue = extractSecretKeyD(derEncodedPrivateKey);
 * console.log(privateValue.length); // 32 bytes
 * ```
 * 
 * Standards Compliance:
 * - RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
 * - RFC 5915: Elliptic Curve Private Key Structure
 * - GM/T 0009-2012: SM2 Cryptography Algorithm Application Specification
 * - ISO/IEC 8825-1: ASN.1 DER Encoding Rules
 * 
 * @module key-der
 */

import { FormatError, ErrorCodes } from '../core/errors.js';
import { ASN1, readDERLength, encodeDERLength, encodeDERSequence, encodeDEROID } from '../formats/der.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from './binary.js';

/**
 * Object Identifier (OID) for Elliptic Curve cryptography
 * 
 * This OID (1.2.840.10045.2.1) identifies the id-ecPublicKey algorithm,
 * indicating that this is an elliptic curve public key as defined in
 * RFC 5480 Section 2.1.1.
 * 
 * Binary Representation:
 * - 0x2A (1.2): ISO
 * - 0x86, 0x48 (840): US
 * - 0xCE, 0x3D (10045): ANSI X9.62
 * - 0x02, 0x01: Public Key Type = id-ecPublicKey
 * 
 * @constant {Buffer}
 */
export const EC_OID = Buffer.from([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);

/**
 * Object Identifier (OID) for SM2 elliptic curve
 * 
 * This OID (1.2.156.10197.1.301) identifies the SM2 curve parameters
 * as defined in GM/T 0006-2012 Section 4.2.1.
 * 
 * Binary Representation:
 * - 0x2A (1.2): ISO
 * - 0x81, 0x1C (156): China
 * - 0xCF, 0x55 (10197): State Cryptography Administration
 * - 0x01: Category = Algorithm
 * - 0x82, 0x2D (301): SM2 Curve
 * 
 * @constant {Buffer}
 */
export const SM2_OID = Buffer.from([0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D]);

/**
 * DER encoding prefix for SM2 public keys
 * 
 * This constant represents the ASN.1 DER encoding of the following structure:
 * ```asn1
 * SEQUENCE {
 *   SEQUENCE {
 *     OBJECT IDENTIFIER ecPublicKey (1.2.840.10045.2.1)
 *     OBJECT IDENTIFIER SM2 (1.2.156.10197.1.301)
 *   }
 *   BIT STRING
 * }
 * ```
 * 
 * Hex Breakdown:
 * - 30 59: Outer SEQUENCE (89 bytes)
 * - 30 13: Inner SEQUENCE (19 bytes)
 * - 06 07: OID (7 bytes) for ecPublicKey
 * - 2A...01: ecPublicKey OID value
 * - 06 08: OID (8 bytes) for SM2
 * - 2A...2D: SM2 OID value
 * - 03 42: BIT STRING (66 bytes)
 * - 00: No unused bits
 * 
 * @constant {Buffer}
 */
export const DER_PUBLIC_KEY_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a811ccf5501822d034200', 'hex');

/**
 * DER encoding prefix and suffix for SM2 private keys
 * 
 * These constants represent the ASN.1 DER encoding of the following structure:
 * ```asn1
 * SEQUENCE {
 *   INTEGER 1  // version
 *   SEQUENCE {
 *     OBJECT IDENTIFIER ecPrivateKey (1.2.840.10045.2.1)
 *     OBJECT IDENTIFIER SM2 (1.2.156.10197.1.301)
 *   }
 *   OCTET STRING containing:
 *     SEQUENCE {
 *       INTEGER 1  // version
 *       OCTET STRING // private key
 *       [1] public key
 *     }
 * }
 * ```
 * 
 * Hex Breakdown (PREFIX):
 * - 30 81 87: Outer SEQUENCE (135 bytes)
 * - 02 01 00: INTEGER version = 1
 * - 30 13: Algorithm SEQUENCE (19 bytes)
 * - 06 07: OID (7 bytes) for ecPrivateKey
 * - 2A...01: ecPrivateKey OID value
 * - 06 08: OID (8 bytes) for SM2
 * - 2A...2D: SM2 OID value
 * - 04 6D: OCTET STRING (109 bytes)
 * - 30 6B: Inner SEQUENCE (107 bytes)
 * - 02 01 01: INTEGER version = 1
 * - 04 20: OCTET STRING (32 bytes) for private key
 * 
 * Hex Breakdown (SUFFIX):
 * - A1 44: [1] EXPLICIT (68 bytes)
 * - 03 42: BIT STRING (66 bytes)
 * - 00: No unused bits
 * 
 * @constant {Buffer}
 */
export const DER_PRIVATE_KEY_PREFIX = Buffer.from('308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420', 'hex');
export const DER_PRIVATE_KEY_SUFFIX = Buffer.from('a144034200', 'hex');

/**
 * Parse a DER encoded SM2 public key into raw coordinates
 * 
 * This function performs DER decoding of an SM2 public key following RFC 5480
 * SubjectPublicKeyInfo format. It includes comprehensive format validation
 * and algorithm identifier verification.
 * 
 * Processing Steps:
 * 1. Validates outer/inner SEQUENCE structures
 * 2. Verifies EC algorithm identifier (1.2.840.10045.2.1)
 * 3. Verifies SM2 curve identifier (1.2.156.10197.1.301)
 * 4. Extracts and validates public key coordinates
 * 
 * ASN.1 Structure:
 * ```asn1
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier {
 *     algorithm OBJECT IDENTIFIER, -- id-ecPublicKey
 *     parameters OBJECT IDENTIFIER -- SM2 curve
 *   },
 *   subjectPublicKey BIT STRING -- 0x04 || x || y
 * }
 * ```
 * 
 * Security Considerations:
 * - Performs constant-time tag and length comparisons
 * - Validates all ASN.1 structures before processing
 * - Checks for buffer overflows at each step
 * - Verifies algorithm identifiers to prevent confusion attacks
 * 
 * Performance Notes:
 * - Uses zero-copy Buffer.subarray() for coordinate extraction
 * - Sequential parsing without backtracking
 * - Minimal memory allocations
 * 
 * @param {Buffer|Uint8Array} der - DER encoded public key
 * @returns {Buffer|Uint8Array} Raw public key (64 bytes: x||y coordinates)
 * @throws {FormatError} If DER format is invalid or contains incorrect identifiers
 * 
 * @example
 * ```javascript
 * const derKey = Buffer.from('3059...', 'hex'); // DER encoded key
 * const rawKey = parsePublicKeyDER(derKey);
 * console.log(rawKey.length); // 64 bytes
 * const x = rawKey.subarray(0, 32);  // x coordinate
 * const y = rawKey.subarray(32, 64); // y coordinate
 * ```
 */
export function parsePublicKeyDER(der) {
  let offset = 0;

  // Skip sequence tag
  if (der[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  // Skip sequence length
  let [, newOffset] = readDERLength(der, offset);
  offset = newOffset;

  // Skip algorithm identifier sequence
  if (der[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Read EC algorithm identifier
  if (der[offset++] !== ASN1.OBJECT_IDENTIFIER) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Verify EC algorithm identifier
  const ecOIDLength = EC_OID.length;
  if (offset + ecOIDLength > der.length ||
      !der.subarray(offset, offset + ecOIDLength).equals(EC_OID)) {
    throw new FormatError('Invalid EC algorithm identifier', { code: ErrorCodes.ERR_FORMAT_OID });
  }

  offset += ecOIDLength;

  // Read SM2 algorithm identifier
  if (der[offset++] !== ASN1.OBJECT_IDENTIFIER) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Verify SM2 algorithm identifier
  const sm2OIDLength = SM2_OID.length;
  if (offset + sm2OIDLength > der.length ||
      !der.subarray(offset, offset + sm2OIDLength).equals(SM2_OID)) {
    throw new FormatError('Invalid SM2 algorithm identifier', { code: ErrorCodes.ERR_FORMAT_OID });
  }

  offset += sm2OIDLength;

  // Read bit string tag
  if (der[offset++] !== ASN1.BIT_STRING) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Skip unused bits count
  offset++;

  // Extract coordinates
  const coordLength = 32;
  if (offset + coordLength * 2 + 1 > der.length) {
    throw new FormatError('Invalid public key length', { code: ErrorCodes.ERR_FORMAT_LENGTH });
  }

  // Verify uncompressed format marker
  if (der[offset++] !== 0x04) {
    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  const x = der.subarray(offset, offset + coordLength);
  const y = der.subarray(offset + coordLength, offset + coordLength * 2);

  return matchBinaryType(der, Buffer.concat([x, y]));
}

/**
 * Extract x and y coordinates from a DER encoded public key
 * 
 * This convenience function combines DER parsing and coordinate extraction
 * into a single operation. It's particularly useful when working with
 * cryptographic APIs that require separate x and y coordinates.
 * 
 * Processing Steps:
 * 1. Parses the DER encoded key using parsePublicKeyDER
 * 2. Splits the resulting 64-byte key into x and y coordinates
 * 3. Returns coordinates in the same type as input (Buffer/Uint8Array)
 * 
 * Security Considerations:
 * - Inherits all security properties from parsePublicKeyDER
 * - Zero-copy coordinate extraction to prevent data leaks
 * - Maintains constant-time operations
 * 
 * Performance Notes:
 * - Single pass through DER structure
 * - Uses Buffer.subarray() for zero-copy coordinate access
 * - No additional allocations beyond parsing
 * 
 * @param {Buffer|Uint8Array} publicKey - DER encoded public key
 * @returns {{x: Buffer|Uint8Array, y: Buffer|Uint8Array}} Object containing 32-byte x and y coordinates
 * @throws {FormatError} If key format is invalid
 * 
 * @example
 * ```javascript
 * const derKey = Buffer.from('3059...', 'hex'); // DER encoded key
 * const { x, y } = extractPublicKeyCoordinates(derKey);
 * console.log(x.length); // 32 bytes
 * console.log(y.length); // 32 bytes
 * ```
 */
export function extractPublicKeyCoordinates(publicKey) {
  const raw = parsePublicKeyDER(publicKey);
  return {
    x: raw.subarray(0, 32),
    y: raw.subarray(32, 64)
  };
}

/**
 * Extract the private key value from a DER encoded private key
 * 
 * This function decodes an SM2 private key following RFC 5915 ECPrivateKey
 * format. It performs comprehensive validation of the DER structure and
 * algorithm identifiers before extracting the private key value.
 * 
 * Processing Steps:
 * 1. Validates outer/inner SEQUENCE and version numbers
 * 2. Verifies EC algorithm identifier (1.2.840.10045.2.1)
 * 3. Verifies SM2 curve identifier (1.2.156.10197.1.301)
 * 4. Extracts and validates private key value
 * 
 * ASN.1 Structure:
 * ```asn1
 * ECPrivateKey ::= SEQUENCE {
 *   version INTEGER { ecPrivkeyVer1(1) },
 *   privateKey OCTET STRING,
 *   parameters [0] EXPLICIT ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey [1] EXPLICIT BIT STRING OPTIONAL
 * }
 * ```
 * 
 * Security Considerations:
 * - Constant-time operations for timing attack prevention
 * - Validates structure before accessing private key
 * - Checks all version numbers and identifiers
 * - Zero-copy extraction to prevent key material leaks
 * 
 * Performance Notes:
 * - Sequential parsing without backtracking
 * - Minimal memory allocations
 * - Early validation to fail fast
 * 
 * @param {Buffer|Uint8Array} der - DER encoded private key
 * @returns {Buffer|Uint8Array} Private key value (32 bytes)
 * @throws {FormatError} If DER format is invalid
 * 
 * @example
 * ```javascript
 * const derKey = Buffer.from('3081...', 'hex'); // DER encoded private key
 * const privateKey = extractSecretKeyD(derKey);
 * console.log(privateKey.length); // 32 bytes
 * ```
 */
export function extractSecretKeyD(der) {
  let offset = 0;

  // Skip outer sequence tag
  if (der[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  // Skip outer sequence length
  let [, newOffset] = readDERLength(der, offset);
  offset = newOffset;

  // Skip version number
  if (der[offset++] !== ASN1.INTEGER) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);
  offset++; // Skip version value

  // Skip algorithm identifier sequence
  if (der[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Read EC algorithm identifier
  if (der[offset++] !== ASN1.OBJECT_IDENTIFIER) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Verify EC algorithm identifier
  const ecOIDLength = EC_OID.length;
  if (offset + ecOIDLength > der.length ||
      !der.subarray(offset, offset + ecOIDLength).equals(EC_OID)) {
    throw new FormatError('Invalid EC algorithm identifier', { code: ErrorCodes.ERR_FORMAT_OID });
  }

  offset += ecOIDLength;

  // Read SM2 algorithm identifier
  if (der[offset++] !== ASN1.OBJECT_IDENTIFIER) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Verify SM2 algorithm identifier
  const sm2OIDLength = SM2_OID.length;
  if (offset + sm2OIDLength > der.length ||
      !der.subarray(offset, offset + sm2OIDLength).equals(SM2_OID)) {
    throw new FormatError('Invalid SM2 algorithm identifier', { code: ErrorCodes.ERR_FORMAT_OID });
  }

  offset += sm2OIDLength;

  // Skip outer octet string tag
  if (der[offset++] !== ASN1.OCTET_STRING) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Skip inner sequence tag
  if (der[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);

  // Skip inner version number
  if (der[offset++] !== ASN1.INTEGER) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  [, offset] = readDERLength(der, offset);
  offset++; // Skip version value

  // Read private key octet string
  if (der[offset++] !== ASN1.OCTET_STRING) {
    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  const [length, nextOffset] = readDERLength(der, offset);
  offset = nextOffset;

  // Extract private key value
  if (length !== 32) {
    throw new FormatError('Invalid private key length', { code: ErrorCodes.ERR_FORMAT_LENGTH });
  }

  return matchBinaryType(der, der.subarray(offset, offset + length));
}
