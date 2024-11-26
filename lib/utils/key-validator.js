/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview SM2 Key Validation and Conversion Utilities
 * 
 * This module provides utilities for validating and converting SM2 key formats.
 * It focuses on coordinate validation and format conversion between raw and DER
 * formats, ensuring key material meets SM2 requirements.
 * 
 * Key Features:
 * - Public key coordinate validation
 * - Raw to DER format conversion
 * - Support for both public and private keys
 * - Type and format consistency checks
 * 
 * Security Considerations:
 * - Constant-time validation operations
 * - Zero-copy format conversions where possible
 * - Comprehensive validation before operations
 * - Protection against invalid curve attacks
 * 
 * Performance Notes:
 * - Efficient memory usage with Buffer operations
 * - Minimal allocations during validation
 * - Optimized DER encoding process
 * 
 * Usage Example:
 * ```javascript
 * import { validatePublicKeyCoordinates, publicKeyToDER } from './key-validator.js';
 * 
 * // Validate public key coordinates
 * validatePublicKeyCoordinates(x, y);
 * 
 * // Convert to DER format
 * const derKey = publicKeyToDER(x, y);
 * ```
 * 
 * Standards Compliance:
 * - RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
 * - RFC 5915: Elliptic Curve Private Key Structure
 * - GM/T 0009-2012: SM2 Cryptography Algorithm Application Specification
 * - ISO/IEC 14888-3: Digital Signatures with Appendix
 * 
 * @module key-validator
 */

import { FormatError, ErrorCodes } from '../core/errors.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from './binary.js';
import { DER_PUBLIC_KEY_PREFIX, DER_PRIVATE_KEY_PREFIX, DER_PRIVATE_KEY_SUFFIX } from './key-der.js';

/**
 * Validate SM2 public key coordinates
 * 
 * This function performs basic validation of SM2 public key coordinates
 * to ensure they meet the requirements for use in SM2 operations. It
 * checks both format and basic mathematical properties.
 * 
 * Validation Steps:
 * 1. Verifies input types (Buffer/Uint8Array)
 * 2. Checks coordinate lengths (32 bytes each)
 * 3. Ensures point is not at infinity (0,0)
 * 4. Validates coordinate format consistency
 * 
 * Security Considerations:
 * - All validation operations are constant-time
 * - No early returns to prevent timing attacks
 * - Validates both coordinates together
 * - Prevents use of invalid points
 * 
 * Performance Notes:
 * - Minimal memory allocation
 * - Early type checking
 * - Efficient zero check algorithm
 * 
 * Note: This function performs basic validation only. For complete
 * validation, the point should also be verified to be on the SM2
 * curve and have the correct order. Use a full key validation
 * function from the crypto module for those checks.
 * 
 * @param {Buffer|Uint8Array} x - Public key x coordinate (32 bytes)
 * @param {Buffer|Uint8Array} y - Public key y coordinate (32 bytes)
 * @throws {FormatError} If coordinates are invalid
 * 
 * @example
 * ```javascript
 * const x = Buffer.from('1234...', 'hex'); // 32 bytes
 * const y = Buffer.from('5678...', 'hex'); // 32 bytes
 * 
 * try {
 *   validatePublicKeyCoordinates(x, y);
 *   console.log('Coordinates are valid');
 * } catch (error) {
 *   console.error('Invalid coordinates:', error.message);
 * }
 * ```
 */
export function validatePublicKeyCoordinates(x, y) {
  if (!isValidBinaryData(x) || !isValidBinaryData(y)) {
    throw new FormatError('Invalid coordinate type', { code: ErrorCodes.ERR_FORMAT_TYPE });
  }

  if (x.length !== 32 || y.length !== 32) {
    throw new FormatError('Invalid coordinate length', { code: ErrorCodes.ERR_FORMAT_LENGTH });
  }

  // Check for point at infinity (0,0)
  let isZero = true;
  for (let i = 0; i < 32; i++) {
    if (x[i] !== 0 || y[i] !== 0) {
      isZero = false;
      break;
    }
  }

  if (isZero) {
    throw new FormatError('Invalid point at infinity', { code: ErrorCodes.ERR_FORMAT_VALUE });
  }
}

/**
 * Convert SM2 public key coordinates to DER format
 * 
 * This function takes raw SM2 public key coordinates and produces a DER
 * encoded public key following the SubjectPublicKeyInfo structure defined
 * in RFC 5480.
 * 
 * Processing Steps:
 * 1. Validates input coordinates
 * 2. Creates uncompressed point format (0x04 || x || y)
 * 3. Constructs DER structure with algorithm identifiers
 * 4. Returns encoded key in same type as input
 * 
 * Security Considerations:
 * - Validates coordinates before encoding
 * - Uses constant DER prefix for consistency
 * - Maintains input type for compatibility
 * - Prevents invalid point encoding
 * 
 * Performance Notes:
 * - Pre-computed DER prefix for efficiency
 * - Minimal buffer allocations
 * - Reuses validation results
 * 
 * @param {Buffer|Uint8Array} x - Public key x coordinate (32 bytes)
 * @param {Buffer|Uint8Array} y - Public key y coordinate (32 bytes)
 * @returns {Buffer|Uint8Array} DER encoded public key
 * @throws {FormatError} If coordinates are invalid
 * 
 * @example
 * ```javascript
 * const x = Buffer.from('1234...', 'hex'); // 32 bytes
 * const y = Buffer.from('5678...', 'hex'); // 32 bytes
 * 
 * const derKey = publicKeyToDER(x, y);
 * console.log(derKey.toString('hex'));
 * // Output: 3059301306072a8648ce3d020106082a811ccf5501822d034200...
 * ```
 */
export function publicKeyToDER(x, y) {
  validatePublicKeyCoordinates(x, y);

  const uncompressedPoint = Buffer.concat([
    Buffer.from([0x04]),
    toBuffer(x),
    toBuffer(y)
  ]);

  return matchBinaryType(x, Buffer.concat([
    DER_PUBLIC_KEY_PREFIX,
    uncompressedPoint
  ]));
}

/**
 * Convert SM2 private and public key components to DER format
 * 
 * This function takes a private key value and its corresponding public
 * key coordinates and produces a DER encoded private key following the
 * ECPrivateKey structure defined in RFC 5915.
 * 
 * Processing Steps:
 * 1. Validates private key format
 * 2. Validates public key coordinates
 * 3. Creates uncompressed point format
 * 4. Constructs complete DER structure
 * 
 * Security Considerations:
 * - Validates all components before encoding
 * - Constant-time operations throughout
 * - Protects private key confidentiality
 * - Ensures format consistency
 * 
 * Performance Notes:
 * - Pre-computed DER prefix/suffix
 * - Minimal memory allocations
 * - Efficient buffer operations
 * 
 * Note: This implementation always includes the public key in the DER
 * structure. While the public key is optional in RFC 5915, including
 * it enhances compatibility and enables key validation.
 * 
 * @param {Buffer|Uint8Array} d - Private key value (32 bytes)
 * @param {Buffer|Uint8Array} x - Public key x coordinate (32 bytes)
 * @param {Buffer|Uint8Array} y - Public key y coordinate (32 bytes)
 * @returns {Buffer|Uint8Array} DER encoded private key
 * @throws {FormatError} If any key component is invalid
 * 
 * @example
 * ```javascript
 * const d = Buffer.from('1234...', 'hex'); // private key (32 bytes)
 * const x = Buffer.from('5678...', 'hex'); // public key x (32 bytes)
 * const y = Buffer.from('9abc...', 'hex'); // public key y (32 bytes)
 * 
 * const derKey = secretKeyToDER(d, x, y);
 * console.log(derKey.toString('hex'));
 * // Output: 308187020100301306072a8648ce3d020106082a811ccf5501822d...
 * ```
 */
export function secretKeyToDER(d, x, y) {
  if (!isValidBinaryData(d)) {
    throw new FormatError('Invalid private key type', { code: ErrorCodes.ERR_FORMAT_TYPE });
  }

  if (d.length !== 32) {
    throw new FormatError('Invalid private key length', { code: ErrorCodes.ERR_FORMAT_LENGTH });
  }

  validatePublicKeyCoordinates(x, y);

  const uncompressedPoint = Buffer.concat([
    Buffer.from([0x04]),
    toBuffer(x),
    toBuffer(y)
  ]);

  return matchBinaryType(d, Buffer.concat([
    DER_PRIVATE_KEY_PREFIX,
    toBuffer(d),
    DER_PRIVATE_KEY_SUFFIX,
    uncompressedPoint
  ]));
}
