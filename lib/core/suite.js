/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview SM2 2023 Cryptographic Suite Implementation
 * 
 * This module exports the SM2 2023 cryptographic suite for Data Integrity Proofs.
 * It provides a comprehensive implementation of the SM2 signature suite, following
 * the W3C Data Integrity specification and GB/T standards.
 * 
 * Key Features:
 * - Digital signature creation and verification
 * - Document canonicalization using URDNA2015
 * - Compatibility with Data Integrity API
 * - Support for SM2 algorithm (GB/T 32918)
 * 
 * Standards Compliance:
 * - W3C Data Integrity 1.0
 * - GB/T 32918.1-2016 (SM2)
 * - GB/T 32905-2016 (SM3)
 * - RDF Dataset Normalization 1.0
 * 
 * Usage Example:
 * ```javascript
 * import { cryptosuite } from './suite.js';
 * 
 * // Create a verifier for a document
 * const verifier = cryptosuite.createVerifier({
 *   publicKey: publicKeyBytes,
 *   document: document
 * });
 * 
 * // Canonicalize a document
 * const canonicalized = await cryptosuite.canonize(document);
 * 
 * // Get suite information
 * console.log(cryptosuite.name);         // 'sm2-2023'
 * console.log(cryptosuite.algorithm);    // 'SM2'
 * ```
 * 
 * Security Considerations:
 * - Implements SM2 digital signatures (256-bit security)
 * - Uses SM3 hash function for message digests
 * - Ensures deterministic document canonicalization
 * - Follows cryptographic best practices
 * 
 * @module suite/index
 * @see {@link https://w3c.github.io/vc-data-integrity/|Data Integrity}
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 */

import jsonld from 'jsonld';
import { SM2Multikey } from './multikey.js';

/**
 * Required Cryptographic Algorithm
 * 
 * This constant defines the required cryptographic algorithm for the
 * suite as 'SM2'. This identifier is used to validate key compatibility,
 * identify signature algorithms, configure cryptographic operations,
 * and ensure protocol compliance.
 * 
 * @constant {string}
 * @default 'SM2'
 */
const requiredAlgorithm = 'SM2';

/**
 * SM2 Cryptographic Suite Name
 * 
 * The standardized identifier for the SM2 2023 cryptographic suite.
 * Used in proof type identification, suite registration,
 * compatibility verification, and document validation.
 * 
 * @constant {string}
 * @default 'sm2-2023'
 */
const name = 'sm2-2023';

/**
 * Canonicalizes a JSON-LD document using URDNA2015 algorithm
 * 
 * @param {Object|string} input - JSON-LD document to canonicalize
 * @param {Object} [options] - Canonicalization options
 * @returns {string} Canonicalized N-Quads string
 * @throws {jsonld.JsonLdError} If canonicalization fails
 */
function canonize(input, options) {
  return jsonld.canonize(input, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    ...options
  });
}

/**
 * Creates a verifier for SM2 digital signatures
 * 
 * @param {object} options - Verifier creation options
 * @param {object} options.verificationMethod - Verification method object
 * @returns {object} Verifier object with verify() method
 * @throws {Error} If verification method is invalid
 */
function createVerifier({verificationMethod}) {
  const key = SM2Multikey.from(verificationMethod);
  return key.verifier();
}

/**
 * SM2 2023 Cryptographic Suite
 * 
 * A comprehensive implementation of the SM2 signature suite that provides
 * all necessary functionality for creating and verifying Data Integrity Proofs.
 * 
 * Components:
 * - canonize: Document canonicalization function
 * - createVerifier: Signature verification factory
 * - name: Suite identifier string
 * - requiredAlgorithm: Required crypto algorithm
 * 
 * Implementation Details:
 * - Uses URDNA2015 for canonicalization
 * - Implements SM2 signature verification
 * - Provides suite identification
 * - Ensures algorithm compatibility
 * 
 * @type {object}
 * @property {Function} canonize - Document canonicalization function
 * @property {Function} createVerifier - Creates a signature verifier
 * @property {string} name - Suite name identifier
 * @property {string} requiredAlgorithm - Required algorithm ('SM2')
 * 
 * @example
 * // Basic suite usage
 * const suite = cryptosuite;
 * const verifier = suite.createVerifier(options);
 * const canonical = await suite.canonize(document);
 * 
 * @example
 * // Suite information
 * console.log(suite.name);            // 'sm2-2023'
 * console.log(suite.requiredAlgorithm); // 'SM2'
 */
export const cryptosuite = {
  canonize,
  createVerifier,
  name,
  requiredAlgorithm,
};
