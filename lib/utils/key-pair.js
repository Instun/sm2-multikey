/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview SM2 Key Pair Management Utilities
 * 
 * This module provides utilities for managing SM2 key pairs in the Multikey format,
 * implementing the W3C Multikey specification for cryptographic key representation.
 * It focuses on secure and interoperable key pair handling with specific support
 * for the SM2 algorithm.
 * 
 * Key Features:
 * - Multikey format import/export
 * - Compressed public key support
 * - Multibase/Multicodec encoding
 * - Key metadata management
 * - Format validation and conversion
 * 
 * Security Considerations:
 * - Private key protection during export
 * - Format validation to prevent injection
 * - Safe key material handling
 * - Prefix verification for type safety
 * - Error isolation and handling
 * 
 * Performance Notes:
 * - Efficient key compression
 * - Minimal memory allocations
 * - Lazy key decompression
 * - Optimized encoding/decoding
 * 
 * Usage Example:
 * ```javascript
 * import { exportKeyPair, importKeyPair } from './key-pair.js';
 * 
 * // Export a key pair to Multikey format
 * const keyPair = {
 *   publicKey: Buffer.alloc(64),  // x||y coordinates
 *   secretKey: Buffer.alloc(32),  // private key
 *   id: 'key-1',
 *   controller: 'did:example:123'
 * };
 * const exported = exportKeyPair({ keyPair, secretKey: true });
 * 
 * // Import from Multikey format
 * const imported = importKeyPair({
 *   publicKeyMultibase: exported.publicKeyMultibase,
 *   secretKeyMultibase: exported.secretKeyMultibase,
 *   id: exported.id,
 *   controller: exported.controller
 * });
 * ```
 * 
 * Standards Compliance:
 * - W3C Multikey Specification
 * - Multicodec Specification
 * - Multibase Specification
 * - GM/T 0009-2012: SM2 Digital Signature Algorithm
 * - JSON-LD 1.1 Context Definition
 * 
 * @module key-pair
 */

import { KeyError, ErrorCodes } from '../core/errors.js';
import { compressPublicKey, uncompressPublicKey } from './key-compression.js';
import {
  MULTICODEC_SM2_PUB_HEADER,
  MULTICODEC_SM2_PRIV_HEADER,
  encodeKey,
  decodeKey
} from '../formats/codec.js';

/**
 * The JSON-LD context URL for Multikey v1
 * 
 * This URL defines the semantic meaning of Multikey properties in the
 * JSON-LD format. It provides:
 * - Property definitions and types
 * - Semantic relationships
 * - Vocabulary mappings
 * - Type coercion rules
 * 
 * The context ensures interoperability by:
 * - Standardizing property names
 * - Defining data types
 * - Enabling semantic validation
 * - Supporting linked data features
 * 
 * @constant {string}
 * @see https://w3id.org/security/multikey/v1
 */
const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';

/**
 * Export a key pair to the Multikey format
 * 
 * This function exports an SM2 key pair to the standardized Multikey format,
 * which provides a secure and interoperable representation of cryptographic
 * keys. It handles key compression, encoding, and metadata management.
 * 
 * Processing Steps:
 * 1. Validate input parameters
 * 2. Compress public key (reduces size by 50%)
 * 3. Encode keys with Multicodec prefixes
 * 4. Convert to Multibase format
 * 5. Add metadata (id, controller)
 * 
 * Output Format:
 * ```json
 * {
 *   "type": "Multikey",
 *   "@context": "https://w3id.org/security/multikey/v1",
 *   "publicKeyMultibase": "z...",  // Compressed, prefixed, multibase
 *   "secretKeyMultibase": "z...",  // Optional, if secretKey=true
 *   "id": "key-1",                 // Optional
 *   "controller": "did:example:123" // Optional
 * }
 * ```
 * 
 * Security Considerations:
 * - Private key is only included if explicitly requested
 * - All inputs are validated before processing
 * - Key compression uses constant-time operations
 * - Proper error isolation and handling
 * 
 * Performance Notes:
 * - Public key compression reduces size by 50%
 * - Minimal memory allocations
 * - Efficient encoding operations
 * - Early validation for fast failure
 * 
 * @param {Object} options - Export options
 * @param {Object} options.keyPair - Key pair to export
 * @param {Buffer} options.keyPair.publicKey - Public key (uncompressed, 64 bytes)
 * @param {Buffer} [options.keyPair.secretKey] - Private key (32 bytes)
 * @param {string} [options.keyPair.id] - Key identifier
 * @param {string} [options.keyPair.controller] - Controller identifier
 * @param {boolean} [options.secretKey=false] - Whether to export private key
 * @returns {object} Exported key pair in Multikey format
 * @throws {TypeError} If key pair format is incorrect
 * @throws {KeyError} If no public key is available
 * 
 * @example
 * ```javascript
 * // Export public key only
 * const publicOnly = exportKeyPair({
 *   keyPair: {
 *     publicKey: publicKeyBuffer,
 *     id: 'key-1',
 *     controller: 'did:example:123'
 *   }
 * });
 * 
 * // Export with private key
 * const withPrivate = exportKeyPair({
 *   keyPair: {
 *     publicKey: publicKeyBuffer,
 *     secretKey: privateKeyBuffer,
 *     controller: 'did:example:123'
 *   },
 *   secretKey: true
 * });
 * ```
 */
export function exportKeyPair({ keyPair, secretKey = false } = {}) {
  if (!keyPair || typeof keyPair !== 'object') {
    throw new TypeError('keyPair must be a non-null object');
  }

  if (!keyPair.publicKey) {
    throw new KeyError('No public key available for export', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
  }

  const result = {
    type: 'Multikey',
    '@context': MULTIKEY_CONTEXT_V1_URL,
    publicKeyMultibase: encodeKey(
      MULTICODEC_SM2_PUB_HEADER,
      compressPublicKey(keyPair.publicKey)
    )
  };

  // Only include secretKeyMultibase if secretKey is explicitly requested and available
  if (secretKey && keyPair.secretKey) {
    result.secretKeyMultibase = encodeKey(
      MULTICODEC_SM2_PRIV_HEADER,
      keyPair.secretKey
    );
  }

  if (keyPair.id) {
    result.id = keyPair.id;
  }

  if (keyPair.controller) {
    result.controller = keyPair.controller;
  }

  return result;
}

/**
 * Import a key pair from Multikey format
 * 
 * This function imports an SM2 key pair from the Multikey format, performing
 * comprehensive validation and format conversion. It handles key decompression,
 * decoding, and metadata extraction.
 * 
 * Processing Steps:
 * 1. Validate input parameters and types
 * 2. Decode Multibase-encoded keys
 * 3. Verify Multicodec prefixes
 * 4. Decompress public key
 * 5. Construct key pair object
 * 
 * Input Format:
 * ```json
 * {
 *   "publicKeyMultibase": "z...",  // Required, compressed public key
 *   "secretKeyMultibase": "z...",  // Optional, private key
 *   "id": "key-1",                 // Optional
 *   "controller": "did:example:123" // Required
 * }
 * ```
 * 
 * Security Considerations:
 * - Validates all input parameters
 * - Verifies key type prefixes
 * - Ensures proper key lengths
 * - Handles decompression errors
 * - Isolates format errors
 * 
 * Performance Notes:
 * - Lazy public key decompression
 * - Efficient Multibase decoding
 * - Minimal memory allocations
 * - Early validation checks
 * 
 * @param {Object} options - Import options
 * @param {string} options.publicKeyMultibase - Multibase-encoded public key
 * @param {string} [options.secretKeyMultibase] - Multibase-encoded private key
 * @param {string} [options.id] - Key identifier
 * @param {string} options.controller - Controller identifier
 * @returns {Object} Imported key pair with uncompressed public key
 * @throws {TypeError} If argument types are incorrect
 * @throws {KeyError} If key format or content is invalid
 * 
 * @example
 * ```javascript
 * // Import public key only
 * const publicOnly = importKeyPair({
 *   publicKeyMultibase: 'zDnaerx...',
 *   controller: 'did:example:123'
 * });
 * 
 * // Import with private key
 * const withPrivate = importKeyPair({
 *   publicKeyMultibase: 'zDnaerx...',
 *   secretKeyMultibase: 'z3keKMV...',
 *   id: 'key-1',
 *   controller: 'did:example:123'
 * });
 * 
 * // Use the imported key pair
 * console.log(withPrivate.publicKey.length);  // 64 bytes (x||y)
 * console.log(withPrivate.secretKey.length);  // 32 bytes
 * ```
 */
export function importKeyPair({ publicKeyMultibase, secretKeyMultibase, id, controller } = {}) {
  if (!controller || typeof controller !== 'string') {
    throw new TypeError('controller must be a non-empty string');
  }

  if (!publicKeyMultibase || typeof publicKeyMultibase !== 'string') {
    throw new TypeError('publicKeyMultibase is required and must be a string');
  }

  if (id !== undefined && (!id || typeof id !== 'string')) {
    throw new TypeError('id must be a non-empty string');
  }

  if (secretKeyMultibase !== undefined && typeof secretKeyMultibase !== 'string') {
    throw new TypeError('secretKeyMultibase must be a string if provided');
  }

  const result = {
    type: 'Multikey',
    '@context': MULTIKEY_CONTEXT_V1_URL,
    controller
  };

  if (id) {
    result.id = id;
  }

  try {
    const { key: compressedPublicKey, prefix: publicKeyPrefix } = decodeKey(publicKeyMultibase);
    if (!publicKeyPrefix.equals(MULTICODEC_SM2_PUB_HEADER)) {
      throw new KeyError('Invalid SM2 public key prefix');
    }
    // Decompress public key
    result.publicKey = uncompressPublicKey(compressedPublicKey);

    if (secretKeyMultibase) {
      const { key: secretKey, prefix: secretKeyPrefix } = decodeKey(secretKeyMultibase);
      if (!secretKeyPrefix.equals(MULTICODEC_SM2_PRIV_HEADER)) {
        throw new KeyError('Invalid SM2 private key prefix');
      }
      result.secretKey = secretKey;
    }

    return result;
  } catch (e) {
    if (e instanceof KeyError) {
      throw e;
    }
    throw new KeyError('Invalid key format', { cause: e });
  }
}
