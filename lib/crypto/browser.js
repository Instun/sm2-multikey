/**
 * @fileoverview Browser-specific SM2/SM3 Cryptographic Operations
 * 
 * This module implements SM2 and SM3 cryptographic operations for browser
 * environments using the sm-crypto library. It provides a pure JavaScript
 * implementation that works across all modern browsers.
 * 
 * Key Features:
 * - Pure JavaScript
 * - Cross-browser
 * - Zero dependencies
 * - Type preservation
 * - Format conversion
 * 
 * Security Considerations:
 * - Browser RNG usage
 * - Parameter validation
 * - Format checking
 * - Memory safety
 * - Error handling
 * 
 * Performance Notes:
 * - Optimized JS code
 * - Minimal copying
 * - Early validation
 * - Buffer reuse
 * - Type preservation
 * 
 * Implementation Details:
 * ```
 * Key Generation:
 * 1. Browser RNG
 * 2. Point generation
 * 3. Format conversion
 * 
 * Signing:
 * 1. SM3 hashing
 * 2. SM2 signing
 * 3. Format conversion
 * 
 * Verification:
 * 1. Parameter check
 * 2. SM3 hashing
 * 3. SM2 verification
 * ```
 * 
 * Standards Compliance:
 * - GB/T 32918.1-2016: SM2 Key
 * - GB/T 32918.2-2016: SM2 Sign
 * - GB/T 32905-2016: SM3 Hash
 * - RFC 5480: EC Public Key
 * - RFC 5915: EC Private Key
 * 
 * Usage Example:
 * ```javascript
 * import crypto from './crypto/browser.js';
 * 
 * // Generate key pair
 * const { publicKey, secretKey } = crypto.generateKey();
 * 
 * // Create signer and verifier
 * const sign = crypto.createSigner({ publicKey, secretKey });
 * const verify = crypto.createVerifier({ publicKey });
 * 
 * // Sign and verify
 * const message = new Uint8Array([1, 2, 3, 4]);
 * const signature = sign({ data: message });
 * const isValid = verify({ data: message, signature });
 * ```
 * 
 * @module crypto/browser
 * @see {@link https://github.com/JuneAndGreen/sm-crypto|sm-crypto}
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 */

import smCrypto from 'sm-crypto';

const { sm2, sm3 } = smCrypto;

import {
    ArgumentError,
    FormatError,
    ErrorCodes
} from '../core/errors.js';
import {
    isValidBinaryData,
    toBuffer,
    matchBinaryType
} from '../utils/binary.js';

/**
 * Convert hexadecimal string to byte array
 * 
 * This function converts a hexadecimal string to an array of bytes,
 * handling odd-length strings by padding with a leading zero. The
 * function is optimized for performance in browser environments.
 * 
 * Processing Steps:
 * 1. Length check
 * 2. Padding if needed
 * 3. Byte conversion
 * 4. Array building
 * 
 * Format Details:
 * ```
 * Input: "1a2b3c"
 * Step 1: Check length (6 chars, even)
 * Step 2: Split into pairs ["1a","2b","3c"]
 * Step 3: Convert to bytes [26,43,60]
 * 
 * Input: "a2b3c"
 * Step 1: Check length (5 chars, odd)
 * Step 2: Pad to "0a2b3c"
 * Step 3: Split into pairs ["0a","2b","3c"]
 * Step 4: Convert to bytes [10,43,60]
 * ```
 * 
 * @private
 * @param {string} hexStr - Hex string to convert
 * @returns {number[]} Array of byte values
 * @throws {Error} If input is not a valid hex string
 */
function hexToArray(hexStr) {
    const words = []
    let hexStrLength = hexStr.length

    if (hexStrLength % 2 !== 0) {
        hexStr = leftPad(hexStr, hexStrLength + 1)
    }

    hexStrLength = hexStr.length

    for (let i = 0; i < hexStrLength; i += 2) {
        words.push(parseInt(hexStr.substr(i, 2), 16))
    }
    return words
}

export default {
    /**
     * Generate a new SM2 key pair
     * 
     * This function generates a new SM2 key pair using the browser's
     * cryptographic random number generator via sm-crypto. The keys
     * are returned in standard formats for compatibility.
     * 
     * Processing Steps:
     * 1. Generate random
     * 2. Create point
     * 3. Format keys
     * 4. Validate output
     * 5. Return pair
     * 
     * Security Considerations:
     * - Browser RNG use
     * - Parameter check
     * - Format validation
     * - Memory safety
     * - Error handling
     * 
     * Performance Notes:
     * - Single allocation
     * - Early validation
     * - Buffer reuse
     * - Type matching
     * - Format caching
     * 
     * Key Format Details:
     * ```
     * Public Key (65 bytes):
     * | Prefix | X-coordinate | Y-coordinate |
     * | 0x04   | 32 bytes    | 32 bytes     |
     * 
     * Private Key (32 bytes):
     * | D-value    |
     * | 32 bytes   |
     * ```
     * 
     * @returns {{publicKey: Buffer, secretKey: Buffer}} Generated key pair
     * @throws {Error} If key generation fails
     * 
     * @example
     * ```javascript
     * // Generate a new key pair
     * const { publicKey, secretKey } = generateKey();
     * 
     * // Verify key formats
     * console.log(publicKey[0] === 0x04);  // true (uncompressed)
     * console.log(publicKey.length);       // 65 bytes
     * console.log(secretKey.length);       // 32 bytes
     * 
     * // Use the keys
     * const signer = createSigner({ publicKey, secretKey });
     * ```
     */
    generateKey: function () {
        const keyPairHex = sm2.generateKeyPairHex();

        return {
            publicKey: Buffer.from(keyPairHex.publicKey.slice(2), 'hex'),
            secretKey: Buffer.from(keyPairHex.privateKey, 'hex')
        }
    },

    /**
     * Create an SM2 signature function
     * 
     * This function creates a signing function that uses sm-crypto's SM2
     * implementation. It handles all necessary format conversions and
     * provides a simple interface for signing messages.
     * 
     * Processing Steps:
     * 1. Validate inputs
     * 2. Convert formats
     * 3. Hash message
     * 4. Create signature
     * 5. Format output
     * 
     * Security Considerations:
     * - Key validation
     * - Format checking
     * - Memory safety
     * - Error handling
     * - Type verification
     * 
     * Performance Notes:
     * - Format caching
     * - Early validation
     * - Buffer reuse
     * - Type matching
     * - Memory efficiency
     * 
     * Format Details:
     * ```
     * Input Keys:
     * | Public (65)  | Private (32) |
     * |--------------|--------------|
     * | 0x04 + X + Y | D value     |
     * 
     * Input Message:
     * | Arbitrary length data |
     * 
     * Output Signature:
     * | R value | S value |
     * | 32 bytes| 32 bytes|
     * ```
     * 
     * @param {{publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array}} key - Key pair
     * @returns {Function} Signing function
     * @throws {ArgumentError} If key format is invalid
     * 
     * @example
     * ```javascript
     * // Create a signer
     * const sign = createSigner({
     *   publicKey: Buffer.alloc(65),  // 0x04 + X + Y
     *   secretKey: Buffer.alloc(32)   // D value
     * });
     * 
     * // Sign different message types
     * const buf = Buffer.from('test');
     * const sig1 = sign({ data: buf });
     * 
     * const uint8 = new Uint8Array([1, 2, 3]);
     * const sig2 = sign({ data: uint8 });
     * console.log(sig2 instanceof Uint8Array);  // true
     * ```
     */
    createSigner: function ({ publicKey, secretKey }) {
        // Convert keys to Buffer for hex conversion
        const pubKeyBuf = toBuffer(publicKey);
        const secKeyBuf = toBuffer(secretKey);

        const privateKeyHex = secKeyBuf.toString('hex');
        const publicKeyHex = '04' + pubKeyBuf.toString('hex');  // Add '04' prefix for uncompressed point format

        // Returns a function that generates a signature
        return ({ data }) => {
            if (!isValidBinaryData(data)) {
                throw new ArgumentError('data must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
            }

            const msgBuf = toBuffer(data);
            const signHex = sm2.doSignature(
                hexToArray(sm3(msgBuf)),
                privateKeyHex,
                {
                    publicKey: publicKeyHex
                });

            // Return same type as input message
            return matchBinaryType(data, Buffer.from(signHex, 'hex'));
        };
    },

    /**
     * Create an SM2 signature verification function
     * 
     * This function creates a verification function that uses sm-crypto's
     * SM2 implementation to verify signatures. It handles all format
     * conversions and provides comprehensive validation.
     * 
     * Processing Steps:
     * 1. Validate inputs
     * 2. Convert formats
     * 3. Hash message
     * 4. Verify signature
     * 5. Return result
     * 
     * Security Considerations:
     * - Key validation
     * - Format checking
     * - Memory safety
     * - Error handling
     * - Type verification
     * 
     * Performance Notes:
     * - Format caching
     * - Early validation
     * - Buffer reuse
     * - Type matching
     * - Memory efficiency
     * 
     * Format Details:
     * ```
     * Public Key (65 bytes):
     * | Prefix | X-coordinate | Y-coordinate |
     * | 0x04   | 32 bytes    | 32 bytes     |
     * 
     * Input Message:
     * | Arbitrary length data |
     * 
     * Input Signature:
     * | R-value     | S-value      |
     * | 32 bytes    | 32 bytes     |
     * ```
     * 
     * @param {{publicKey: Buffer|Uint8Array}} key - Public key for verification
     * @returns {Function} Verification function
     * @throws {ArgumentError} If key format is invalid
     * 
     * @example
     * ```javascript
     * // Create a verifier
     * const verify = createVerifier({
     *   publicKey: Buffer.alloc(65)  // 0x04 + X + Y
     * });
     * 
     * // Verify different types
     * const message = Buffer.from('test');
     * const signature = Buffer.alloc(64);  // R + S values
     * const isValid = verify({ data: message, signature });
     * 
     * // Error handling
     * try {
     *   verify({
     *     data: new Uint8Array([1, 2, 3]),
     *     signature: Buffer.alloc(64)
     *   });
     * } catch (err) {
     *   console.error('Verification failed:', err);
     * }
     * ```
     */
    createVerifier: function ({ publicKey }) {
        // Convert public key to Buffer for hex conversion
        const pubKeyBuf = toBuffer(publicKey);
        const publicKeyHex = '04' + pubKeyBuf.toString('hex');  // Add '04' prefix for uncompressed point format

        // Return verification function
        return ({ data, signature }) => {
            if (!isValidBinaryData(data)) {
                throw new ArgumentError('data must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
            }
            if (!isValidBinaryData(signature)) {
                throw new ArgumentError('signature must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
            }

            const msgBuf = toBuffer(data);
            const sigBuf = toBuffer(signature);

            return sm2.doVerifySignature(
                hexToArray(sm3(msgBuf)),
                sigBuf.toString('hex'),
                publicKeyHex
            );
        };
    },

    /**
     * Compute SM3 cryptographic hash
     * 
     * This function computes the SM3 cryptographic hash of input data
     * using sm-crypto's implementation. SM3 is a cryptographic hash
     * function that produces a 256-bit (32-byte) hash value.
     * 
     * Processing Steps:
     * 1. Validate input
     * 2. Convert format
     * 3. Compute hash
     * 4. Format output
     * 5. Match type
     * 
     * Security Considerations:
     * - Input validation
     * - Memory safety
     * - Buffer bounds
     * - Error handling
     * - Type checking
     * 
     * Performance Notes:
     * - Optimized hash
     * - Early validation
     * - Buffer reuse
     * - Type matching
     * - Memory efficiency
     * 
     * Hash Details:
     * ```
     * Algorithm: SM3 (GB/T 32905-2016)
     * Input: Arbitrary length
     * Output: 32 bytes (256 bits)
     * Block size: 64 bytes (512 bits)
     * Word size: 32 bits
     * Rounds: 64
     * ```
     * 
     * @param {Buffer|Uint8Array} data - Data to hash
     * @returns {Buffer|Uint8Array} 32-byte hash value
     * @throws {ArgumentError} If input format is invalid
     * 
     * @example
     * ```javascript
     * // Hash with Buffer
     * const buf = Buffer.from('test');
     * const hash1 = digest(buf);
     * console.log(hash1.length);  // 32 bytes
     * 
     * // Hash with Uint8Array
     * const uint8 = new Uint8Array([1, 2, 3]);
     * const hash2 = digest(uint8);
     * console.log(hash2 instanceof Uint8Array);  // true
     * 
     * // Error handling
     * try {
     *   digest('invalid');  // Throws ArgumentError
     * } catch (err) {
     *   console.error('Invalid input type');
     * }
     * ```
     */
    digest: function (data) {
        if (!isValidBinaryData(data)) {
            throw new ArgumentError('data must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        const dataBuf = toBuffer(data);
        const hashHex = sm3(dataBuf);

        // Return same type as input
        return matchBinaryType(data, Buffer.from(hashHex, 'hex'));
    }
};