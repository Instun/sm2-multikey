/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Node.js Entry Point for SM2 Multikey Library
 * 
 * This module serves as the main entry point for the SM2 Multikey library
 * in Node.js environments. It provides a comprehensive implementation of
 * the SM2 cryptographic algorithm with multikey support.
 * 
 * Key Features:
 * - SM2 key pair generation and management
 * - Digital signature creation and verification
 * - Multiple key format support (JWK, Multibase)
 * - Data Integrity proof compatibility
 * - Native crypto acceleration
 * 
 * Standards Compliance:
 * - GB/T 32918.1-2016 (SM2)
 * - GB/T 32905-2016 (SM3)
 * - W3C Data Integrity 1.0
 * - W3C Verifiable Credentials
 * 
 * Usage Examples:
 * ```javascript
 * import { SM2Multikey, cryptosuite } from '@instun/sm2-multikey';
 * 
 * // Generate a new key pair
 * const key = await SM2Multikey.generate({
 *   controller: 'did:example:123'
 * });
 * 
 * // Create and verify signatures
 * const signer = key.signer();
 * const signature = await signer.sign({ data });
 * const isValid = await key.verifier().verify({ data, signature });
 * 
 * // Use with Data Integrity
 * const suite = {
 *   ...cryptosuite,
 *   signer: () => key.signer(),
 *   verifier: () => key.verifier()
 * };
 * ```
 * 
 * Platform Requirements:
 * - Node.js 16.x or later
 * - OpenSSL 1.1.1 or later
 * - Native crypto module
 * - SM2 curve support
 * 
 * Security Considerations:
 * - Uses hardware acceleration when available
 * - Implements secure key generation
 * - Follows cryptographic best practices
 * - Provides secure defaults
 * 
 * @module index
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 * @see {@link https://w3c.github.io/vc-data-integrity/|Data Integrity}
 */

import { SM2Multikey } from './core/multikey.js';
import { cryptosuite } from './core/suite.js';
import crypto from './crypto/node.js'

/**
 * Configure Node.js Crypto Implementation
 * 
 * Sets up the Node.js native crypto implementation for the SM2Multikey
 * class. This ensures optimal performance and security by using:
 * 
 * - Native crypto operations
 * - Hardware acceleration
 * - Secure random number generation
 * - Platform-specific optimizations
 * 
 * @private
 */
SM2Multikey.setCryptoImpl(crypto);

/**
 * Library Exports
 * 
 * The library exports two main components:
 * 
 * 1. SM2Multikey: Core class for SM2 key operations
 *    - Key generation and management
 *    - Signature creation and verification
 *    - Format conversion (JWK, Multibase)
 *    - Standards compliance
 * 
 * 2. cryptosuite: SM2 2023 cryptographic suite
 *    - Document canonicalization
 *    - Signature verification
 *    - Data Integrity compatibility
 *    - Suite identification
 * 
 * @exports SM2Multikey - Core multikey implementation class
 * @exports cryptosuite - SM2 cryptographic suite implementation
 */
export {
  SM2Multikey,
  cryptosuite
};
