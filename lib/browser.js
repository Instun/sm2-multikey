/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Browser Entry Point for SM2 Multikey Library
 * 
 * This module serves as the main entry point for the SM2 Multikey library
 * in browser environments. It provides a pure JavaScript implementation
 * of the SM2 cryptographic algorithm with multikey support.
 * 
 * Key Features:
 * - Pure JavaScript implementation
 * - Zero native dependencies
 * - Browser-optimized performance
 * - Small bundle size (~150KB)
 * - Tree-shaking support
 * 
 * Standards Compliance:
 * - GB/T 32918.1-2016 (SM2)
 * - GB/T 32905-2016 (SM3)
 * - W3C Data Integrity 1.0
 * - W3C Verifiable Credentials
 * 
 * Usage Examples:
 * ```javascript
 * import { SM2Multikey, cryptosuite } from '@instun/sm2-multikey/browser';
 * 
 * // Generate a new key pair
 * const key = await SM2Multikey.generate({
 *   controller: 'did:example:123'
 * });
 * 
 * // Sign data in browser
 * const signer = key.signer();
 * const signature = await signer.sign({ data });
 * 
 * // Export for storage
 * const exported = key.export({
 *   secretKey: true,
 *   format: 'jwk'
 * });
 * localStorage.setItem('sm2key', JSON.stringify(exported));
 * ```
 * 
 * Browser Compatibility:
 * - Chrome 63+
 * - Firefox 57+
 * - Safari 11.1+
 * - Edge 79+
 * - Opera 50+
 * 
 * Performance Considerations:
 * - Uses WebCrypto when available
 * - Optimized for modern JavaScript engines
 * - Async operations for better UI responsiveness
 * - Memory-efficient implementation
 * 
 * Bundle Size Details:
 * - Core: ~50KB minified
 * - Dependencies: ~100KB minified
 * - Total: ~150KB minified
 * - ~45KB gzipped
 * 
 * Security Notes:
 * - Uses secure random number generation
 * - Implements constant-time operations
 * - Follows browser security best practices
 * - Avoids DOM-based vulnerabilities
 * 
 * @module browser
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 * @see {@link https://w3c.github.io/vc-data-integrity/|Data Integrity}
 */

import { SM2Multikey } from './core/multikey.js';
import { cryptosuite } from './core/suite.js';
import crypto from './crypto/browser.js';

/**
 * Configure Browser Crypto Implementation
 * 
 * Sets up the browser-specific crypto implementation for the SM2Multikey
 * class. This configuration:
 * 
 * - Uses pure JavaScript implementation
 * - Leverages WebCrypto when available
 * - Provides fallback implementations
 * - Ensures cross-browser compatibility
 * 
 * Implementation Details:
 * - SM2 curve operations in pure JS
 * - SM3 hash function implementation
 * - Secure random number generation
 * - Optimized field arithmetic
 * 
 * @private
 */
SM2Multikey.setCryptoImpl(crypto);

/**
 * Library Exports
 * 
 * The browser bundle exports two main components:
 * 
 * 1. SM2Multikey: Core class for SM2 operations
 *    - Pure JavaScript implementation
 *    - No native dependencies
 *    - Browser-optimized performance
 *    - Comprehensive key management
 * 
 * 2. cryptosuite: SM2 2023 cryptographic suite
 *    - Document canonicalization
 *    - Signature verification
 *    - Data Integrity compatibility
 *    - Cross-platform consistency
 * 
 * Usage Considerations:
 * - Import from '/browser' for optimal bundling
 * - Tree-shaking supported for size optimization
 * - Async operations for UI responsiveness
 * - Memory-efficient implementation
 * 
 * @exports SM2Multikey - Core multikey implementation class
 * @exports cryptosuite - SM2 cryptographic suite implementation
 */
export {
  SM2Multikey,
  cryptosuite
};
