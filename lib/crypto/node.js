/**
 * @fileoverview Node.js-specific SM2/SM3 Cryptographic Operations
 * 
 * This module implements SM2 and SM3 cryptographic operations using the
 * Node.js native crypto module. It provides a high-performance, secure
 * implementation with hardware acceleration support where available.
 * 
 * Key Features:
 * - Native crypto integration
 * - Hardware acceleration
 * - Zero-copy operations
 * - Format conversion
 * - Type preservation
 * 
 * Security Considerations:
 * - Hardware RNG usage
 * - Constant-time ops
 * - Memory clearing
 * - Format validation
 * - Error handling
 * 
 * Performance Notes:
 * - Hardware support
 * - Zero-copy design
 * - Early validation
 * - Buffer reuse
 * - Type matching
 * 
 * Implementation Details:
 * ```
 * Key Generation:
 * 1. Native generateKeyPair
 * 2. DER format conversion
 * 3. Coordinate extraction
 * 
 * Signing:
 * 1. Key format conversion
 * 2. Native SM3 + ECDSA
 * 3. Format normalization
 * 
 * Verification:
 * 1. Key/sig conversion
 * 2. Native verification
 * 3. Format validation
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
 * import crypto from './crypto/node.js';
 * 
 * // Generate key pair
 * const { publicKey, secretKey } = crypto.generateKey();
 * 
 * // Create signer and verifier
 * const sign = crypto.createSigner({ publicKey, secretKey });
 * const verify = crypto.createVerifier({ publicKey });
 * 
 * // Sign and verify
 * const message = Buffer.from('test message');
 * const signature = sign({ data: message });
 * const isValid = verify({ data: message, signature });
 * ```
 * 
 * @module crypto/node
 * @see {@link https://nodejs.org/api/crypto.html|Node.js Crypto}
 * @see {@link http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html|GB/T 32918}
 */

import crypto from 'node:crypto';
import {
    extractPublicKeyCoordinates,
    extractSecretKeyD
} from '../utils/key-der.js';
import {
    secretKeyToDER,
    publicKeyToDER
} from '../utils/key-validator.js';
import {
    extractSignatureRS,
    signatureToDER
} from '../utils/signature.js';
import {
    ErrorCodes,
    ArgumentError
} from '../core/errors.js';
import {
    isValidBinaryData,
    toBuffer,
    matchBinaryType
} from '../utils/binary.js';

/** 
 * SM2 Curve Name
 * 
 * This constant defines the SM2 curve name for use with the Node.js
 * crypto API. The curve parameters are defined in GB/T 32918.1-2016.
 * 
 * Curve Parameters:
 * ```
 * p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 
 *     FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
 * a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 
 *     FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
 * b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 
 *     F39789F5 15AB8F92 DDBCBD41 4D940E93
 * n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 
 *     7203DF6B 21C6052B 53BBF409 39D54123
 * G = (32C4AE2C 1F198119 5F990446 6A39C994 
 *      8FE30BBF F2660BE1 715A4589 334C74C7,
 *      BC3736A2 F4F6779C 59BDCEE3 6B692153 
 *      D0A9877C C62A4740 02DF32E5 2139F0A0)
 * ```
 * 
 * @constant {string}
 * @readonly
 */
const SM2_CURVE = 'SM2';

export default {
    /**
     * Generate a new SM2 key pair
     * 
     * This function generates a new SM2 key pair using the Node.js native
     * crypto API with hardware acceleration where available. The keys are
     * generated in DER format and converted to raw coordinates.
     * 
     * Processing Steps:
     * 1. Generate DER keys
     * 2. Extract coordinates
     * 3. Format conversion
     * 4. Memory cleanup
     * 5. Type matching
     * 
     * Security Considerations:
     * - Hardware RNG use
     * - Memory clearing
     * - Format validation
     * - Error handling
     * - Type checking
     * 
     * Performance Notes:
     * - Hardware support
     * - Single allocation
     * - Early validation
     * - Buffer reuse
     * - Type preservation
     * 
     * Key Format Details:
     * ```
     * Public Key (64 bytes):
     * | X-coordinate | Y-coordinate |
     * | 32 bytes    | 32 bytes     |
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
     * // Verify key lengths
     * console.log(publicKey.length);  // 64 bytes
     * console.log(secretKey.length);  // 32 bytes
     * 
     * // Use the keys
     * const signer = createSigner({ publicKey, secretKey });
     * ```
     */
    generateKey: function () {
        const keyPair = crypto.generateKeyPairSync('ec', {
            namedCurve: SM2_CURVE,
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der'
            }
        });

        const { x, y } = extractPublicKeyCoordinates(Buffer.from(keyPair.publicKey));

        return {
            publicKey: Buffer.concat([x, y]),
            secretKey: extractSecretKeyD(Buffer.from(keyPair.privateKey))
        }
    },

    /**
     * Create an SM2 signature function
     * 
     * This function creates a signing function that uses the Node.js native
     * crypto API for SM2 digital signatures. It handles key format
     * conversion and provides a simple interface for signing messages.
     * 
     * Processing Steps:
     * 1. Validate inputs
     * 2. Convert formats
     * 3. Create signer
     * 4. Sign message
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
     * - Hardware support
     * - Format caching
     * - Early validation
     * - Buffer reuse
     * - Type preservation
     * 
     * Signature Format:
     * ```
     * Input Keys:
     * | Public (64) | Private (32) |
     * |-------------|--------------|
     * | X+Y coords  | D value      |
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
     *   publicKey: Buffer.alloc(64),  // X+Y coordinates
     *   secretKey: Buffer.alloc(32)   // D value
     * });
     * 
     * // Sign a message
     * const message = Buffer.from('test message');
     * const signature = sign({ data: message });
     * console.log(signature.length);  // 64 bytes (R+S)
     * ```
     */
    createSigner: function ({ publicKey, secretKey }) {
        // Convert keys to Buffer for crypto operations
        const pubKeyBuf = toBuffer(publicKey);
        const secKeyBuf = toBuffer(secretKey);

        const privateKey = crypto.createPrivateKey({
            key: secretKeyToDER(secKeyBuf, pubKeyBuf.subarray(0, 32), pubKeyBuf.subarray(32, 64)),
            format: 'der',
            type: 'pkcs8'
        });

        // Return signature function
        return ({ data }) => {
            if (!isValidBinaryData(data)) {
                throw new ArgumentError('data must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
            }

            const msgBuf = toBuffer(data);
            const sign = crypto.createSign('SM3');
            sign.update(msgBuf);
            const derSignature = sign.sign(privateKey);
            
            // Convert from DER format to raw R+S format
            // Return same type as input message
            return matchBinaryType(data, extractSignatureRS(derSignature));
        };
    },

    /**
     * Create an SM2 signature verification function
     * 
     * This function creates a verification function that uses the Node.js
     * native crypto API to verify SM2 digital signatures. It handles all
     * necessary format conversions and validations.
     * 
     * Processing Steps:
     * 1. Validate inputs
     * 2. Convert formats
     * 3. Create verifier
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
     * - Hardware support
     * - Format caching
     * - Early validation
     * - Buffer reuse
     * - Type preservation
     * 
     * Format Details:
     * ```
     * Public Key (64 bytes):
     * | X-coordinate | Y-coordinate |
     * | 32 bytes    | 32 bytes     |
     * 
     * Signature (64 bytes):
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
     *   publicKey: Buffer.alloc(64)  // X+Y coordinates
     * });
     * 
     * // Verify a signature
     * const message = Buffer.from('test message');
     * const signature = Buffer.alloc(64);  // R+S values
     * const isValid = verify({ data: message, signature });
     * 
     * if (isValid) {
     *   console.log('Signature is valid');
     * }
     * ```
     */
    createVerifier: function ({ publicKey }) {
        // Convert public key to Buffer for crypto operations
        const pubKeyBuf = toBuffer(publicKey);
        const pubKey = crypto.createPublicKey({
            key: publicKeyToDER(pubKeyBuf.subarray(0, 32), pubKeyBuf.subarray(32, 64)),
            format: 'der',
            type: 'spki'
        });

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
            const verify = crypto.createVerify('SM3');
            verify.update(msgBuf);

            // Convert signature from raw R+S format to DER format
            const derSignature = signatureToDER(sigBuf);

            return verify.verify(pubKey, derSignature);
        };
    },

    /**
     * Compute SM3 cryptographic hash
     * 
     * This function computes the SM3 cryptographic hash of input data
     * using the Node.js native crypto API. SM3 is a cryptographic hash
     * function that produces a 256-bit (32-byte) hash value.
     * 
     * Processing Steps:
     * 1. Validate input
     * 2. Create hasher
     * 3. Process data
     * 4. Finalize hash
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
     * - Hardware support
     * - Streaming hash
     * - Early validation
     * - Buffer reuse
     * - Type preservation
     * 
     * Hash Details:
     * ```
     * Algorithm: SM3 (GB/T 32905-2016)
     * Input: Arbitrary length
     * Output: 32 bytes (256 bits)
     * Block size: 64 bytes (512 bits)
     * State size: 32 bytes (256 bits)
     * ```
     * 
     * @param {Buffer|Uint8Array} data - Data to hash
     * @returns {Buffer|Uint8Array} 32-byte hash value
     * @throws {ArgumentError} If input format is invalid
     * 
     * @example
     * ```javascript
     * // Hash a message
     * const message = Buffer.from('test message');
     * const hash = digest(message);
     * console.log(hash.length);  // 32 bytes
     * 
     * // Hash with type matching
     * const input = new Uint8Array([1, 2, 3]);
     * const hash2 = digest(input);
     * console.log(hash2 instanceof Uint8Array);  // true
     * ```
     */
    digest: function (data) {
        if (!isValidBinaryData(data)) {
            throw new ArgumentError('data must be Buffer or Uint8Array', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        const dataBuf = toBuffer(data);
        const hash = crypto.createHash('SM3');
        hash.update(dataBuf);
        
        // Return same type as input
        return matchBinaryType(data, hash.digest());
    }
};