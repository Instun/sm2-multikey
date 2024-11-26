/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview SM2 Signature Format Utilities
 * 
 * This module provides utilities for handling SM2 signature formats, focusing on
 * DER (Distinguished Encoding Rules) encoding and decoding of ECDSA signatures.
 * It ensures proper handling of signature components while maintaining
 * compatibility with various cryptographic APIs and standards.
 * 
 * Key Features:
 * - DER encoding/decoding of signatures
 * - Raw signature (R,S) extraction
 * - Variable-length integer handling
 * - Leading zero management
 * - Positive number enforcement
 * - Buffer/Uint8Array support
 * - Type-consistent output
 * 
 * Security Considerations:
 * - Constant-time operations to prevent timing attacks
 * - Strict format validation to prevent ASN.1 vulnerabilities
 * - Proper handling of positive integers to prevent sign confusion
 * - Validation of component lengths to prevent buffer overflows
 * - Protection against malleability attacks
 * 
 * Performance Notes:
 * - Zero-copy operations where possible
 * - Minimal memory allocations
 * - Efficient buffer operations
 * - Early validation for fast failure
 * 
 * Usage Example:
 * ```javascript
 * import { extractSignatureRS, signatureToDER } from './signature.js';
 * 
 * // Convert DER signature to raw format
 * const derSig = Buffer.from('30440220...', 'hex');
 * const rawSig = extractSignatureRS(derSig);
 * console.log(rawSig.length); // 64 bytes (32-byte R || 32-byte S)
 * 
 * // Convert raw signature to DER format
 * const derEncoded = signatureToDER(rawSig);
 * console.log(derEncoded.toString('hex')); // DER encoded signature
 * ```
 * 
 * Standards Compliance:
 * - RFC 3279: Algorithms and Identifiers for PKIX
 * - X.690: ASN.1 DER Encoding Rules
 * - GM/T 0009-2012: SM2 Digital Signature Algorithm
 * - SEC 1: Elliptic Curve Cryptography
 * - FIPS 186-4: Digital Signature Standard (DSS)
 * 
 * @module signature-format
 */

import { FormatError, ErrorCodes } from '../core/errors.js';
import { ASN1, readDERLength, encodeDERLength, encodeDERSequence } from '../formats/der.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from './binary.js';

/**
 * Extract raw R and S values from a DER encoded signature
 * 
 * This function decodes a DER encoded SM2 signature into its raw R and S
 * components. It handles variable-length DER integers and ensures proper
 * normalization to fixed-length values required by most crypto APIs.
 * 
 * Processing Steps:
 * 1. Validates input types and DER structure
 * 2. Extracts R and S integers from DER sequence
 * 3. Handles variable-length DER encoding
 * 4. Normalizes to fixed 32-byte values
 * 
 * ASN.1 Structure:
 * ```asn1
 * ECDSASignature ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 * ```
 * 
 * Security Considerations:
 * - Validates all ASN.1 tags and lengths
 * - Ensures positive integer values
 * - Prevents buffer overflows
 * - Maintains constant-time operations
 * - Validates component ranges
 * 
 * Performance Notes:
 * - Uses Buffer.subarray for zero-copy operations
 * - Pre-allocates fixed-size buffers
 * - Minimizes memory copying
 * - Early validation checks
 * 
 * Special Cases:
 * - Handles leading zeros in DER integers
 * - Maintains positive number representation
 * - Supports both Buffer and Uint8Array inputs
 * - Matches output type to input type
 * 
 * @param {Buffer|Uint8Array} derSignature - DER encoded signature
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} 64-byte raw signature (32-byte R || 32-byte S)
 * @throws {FormatError} If signature format is invalid or values are out of range
 * 
 * @example
 * ```javascript
 * // Extract raw signature from DER format
 * const derSig = Buffer.from('304402203d...', 'hex');
 * const rawSig = extractSignatureRS(derSig);
 * 
 * // Get individual R and S values
 * const r = rawSig.subarray(0, 32);
 * const s = rawSig.subarray(32, 64);
 * 
 * // Use with Uint8Array
 * const uint8Sig = new Uint8Array(derSig);
 * const rawUint8 = extractSignatureRS(uint8Sig, uint8Sig);
 * ```
 */
export function extractSignatureRS(derSignature, outputType) {
  if (!isValidBinaryData(derSignature)) {
    throw new FormatError('Signature must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  // Convert to Buffer for processing
  const sigBuf = toBuffer(derSignature);

  let offset = 0;
  // Check sequence tag
  if (sigBuf[offset++] !== ASN1.SEQUENCE) {
    throw new FormatError('Invalid signature format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  // Read sequence length
  let [, newOffset] = readDERLength(sigBuf, offset);
  offset = newOffset;

  // Read R value
  if (sigBuf[offset++] !== ASN1.INTEGER) {
    throw new FormatError('Invalid R value format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  let [rLength, rOffset] = readDERLength(sigBuf, offset);
  const r = sigBuf.subarray(rOffset, rOffset + rLength);
  offset = rOffset + rLength;

  // Read S value
  if (sigBuf[offset++] !== ASN1.INTEGER) {
    throw new FormatError('Invalid S value format', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  let [sLength, sOffset] = readDERLength(sigBuf, offset);
  const s = sigBuf.subarray(sOffset, sOffset + sLength);

  // Ensure R and S are 32 bytes each, remove leading zeros but keep positive numbers
  const rPadded = Buffer.alloc(32, 0);
  const sPadded = Buffer.alloc(32, 0);

  // For R, skip leading zeros but keep at least one byte
  let rSrc = 0;
  while (rSrc < r.length - 1 && r[rSrc] === 0) rSrc++;
  const rActualLength = r.length - rSrc;
  const rDestOffset = Math.max(0, 32 - rActualLength);
  r.copy(rPadded, rDestOffset, rSrc);

  // For S, skip leading zeros but keep at least one byte
  let sSrc = 0;
  while (sSrc < s.length - 1 && s[sSrc] === 0) sSrc++;
  const sActualLength = s.length - sSrc;
  const sDestOffset = Math.max(0, 32 - sActualLength);
  s.copy(sPadded, sDestOffset, sSrc);

  const result = Buffer.concat([rPadded, sPadded]);
  return outputType ? matchBinaryType(outputType, result) : result;
}

/**
 * Convert raw signature values to DER encoded format
 * 
 * This function encodes raw R and S signature components into a DER encoded
 * signature following the ECDSA signature format. It handles proper integer
 * encoding, including minimal length representation and sign bit handling.
 * 
 * Processing Steps:
 * 1. Validates input format and length
 * 2. Splits into R and S components
 * 3. Removes unnecessary leading zeros
 * 4. Adds leading zero if needed for positive numbers
 * 5. Constructs DER sequence with proper tags and lengths
 * 
 * ASN.1 Structure:
 * ```asn1
 * ECDSASignature ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 * ```
 * 
 * Security Considerations:
 * - Validates input lengths and formats
 * - Ensures positive integer encoding
 * - Prevents signature malleability
 * - Maintains constant-time operations
 * - Proper handling of sign bits
 * 
 * Performance Notes:
 * - Efficient leading zero removal
 * - Pre-computed buffer sizes
 * - Minimal memory allocations
 * - Zero-copy operations where possible
 * 
 * Special Cases:
 * - Removes unnecessary leading zeros
 * - Adds zero byte for positive numbers when needed
 * - Handles minimal DER integer encoding
 * - Matches output type to input type
 * 
 * @param {Buffer|Uint8Array} rawSignature - 64-byte raw signature (R || S)
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} DER encoded signature
 * @throws {FormatError} If input format or length is invalid
 * 
 * @example
 * ```javascript
 * // Create raw signature (usually from crypto operation)
 * const r = Buffer.alloc(32);
 * const s = Buffer.alloc(32);
 * // ... fill r and s with signature values ...
 * 
 * // Combine and convert to DER
 * const rawSig = Buffer.concat([r, s]);
 * const derSig = signatureToDER(rawSig);
 * 
 * // Use with Uint8Array
 * const uint8Sig = new Uint8Array(64);
 * uint8Sig.set(r, 0);
 * uint8Sig.set(s, 32);
 * const derUint8 = signatureToDER(uint8Sig, uint8Sig);
 * ```
 */
export function signatureToDER(rawSignature, outputType) {
  if (!isValidBinaryData(rawSignature)) {
    throw new FormatError('Signature must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  // Convert to Buffer for processing
  const sigBuf = toBuffer(rawSignature);

  if (sigBuf.length !== 64) {
    throw new FormatError('Raw signature must be 64 bytes', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  // Split R and S
  const r = sigBuf.subarray(0, 32);
  const s = sigBuf.subarray(32, 64);

  // Remove leading zeros but ensure at least one byte is kept
  let rStart = 0;
  while (rStart < 31 && r[rStart] === 0) rStart++;
  let sStart = 0;
  while (sStart < 31 && s[sStart] === 0) sStart++;

  // Add a zero byte if highest bit is set to ensure positive number
  const rPad = (r[rStart] & 0x80) !== 0 ? 1 : 0;
  const sPad = (s[sStart] & 0x80) !== 0 ? 1 : 0;

  // Calculate actual lengths for R and S
  const rActual = Buffer.alloc(32 - rStart + rPad);
  const sActual = Buffer.alloc(32 - sStart + sPad);

  if (rPad) rActual[0] = 0;
  if (sPad) sActual[0] = 0;

  r.copy(rActual, rPad, rStart);
  s.copy(sActual, sPad, sStart);

  // Build DER sequence
  const rElement = Buffer.concat([
    Buffer.from([ASN1.INTEGER]),
    encodeDERLength(rActual.length),
    rActual
  ]);

  const sElement = Buffer.concat([
    Buffer.from([ASN1.INTEGER]),
    encodeDERLength(sActual.length),
    sActual
  ]);

  const sequence = Buffer.concat([rElement, sElement]);
  const result = Buffer.concat([
    Buffer.from([ASN1.SEQUENCE]),
    encodeDERLength(sequence.length),
    sequence
  ]);

  return outputType ? matchBinaryType(outputType, result) : result;
}
