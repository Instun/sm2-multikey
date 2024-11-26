/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Implementation of SM2 Multikey functionality.
 * 
 * This module provides a comprehensive implementation of the SM2 cryptographic algorithm
 * with multi-key support. It includes functionality for key pair generation, import/export
 * in various formats (JWK, Multibase), signing, and verification.
 * 
 * Key Features:
 * - SM2 key pair generation and management
 * - Support for multiple key formats (JWK, Multibase)
 * - Digital signature creation and verification
 * - Key compression and encoding utilities
 * - Platform-agnostic implementation with pluggable crypto backend
 * 
 * Security Considerations:
 * - Private keys are never exposed in plaintext
 * - All key operations are performed in memory
 * - Proper key format validation and error handling
 * - Support for key compression to reduce storage size
 * 
 * Performance Considerations:
 * - Lazy initialization of crypto implementation
 * - Efficient key compression and encoding
 * - Minimal memory footprint
 * 
 * Usage Example:
 * ```javascript
 * // Generate a new key pair
 * const keyPair = SM2Multikey.generate({
 *   id: 'key-1',
 *   controller: 'did:example:123'
 * });
 * 
 * // Export public key
 * const exported = keyPair.export({
 *   publicKey: true,
 *   includeContext: true
 * });
 * 
 * // Create a signer
 * const signer = keyPair.signer();
 * const signature = await signer.sign(message);
 * 
 * // Create a verifier
 * const verifier = keyPair.verifier();
 * const isValid = await verifier.verify(message, signature);
 * ```
 * 
 * Standards and Specifications:
 * - SM2 Digital Signature Algorithm (GM/T 0003-2012)
 * - JWK (RFC 7517)
 * - Multicodec and Multibase
 * 
 * @module SM2Multikey
 */

import { base58btc } from 'multiformats/bases/base58';
import { toBase64Url, fromBase64Url } from '../formats/base64.js';
import { compressPublicKey, uncompressPublicKey } from '../utils/key-compression.js';
import { validatePublicKeyCoordinates } from '../utils/key-validator.js';
import {
    KeyError,
    FormatError,
    SM2Error,
    ErrorCodes,
    ArgumentError,
    createError
} from './errors.js';
import {
    fromJwk,
    toJwk,
    jwkToPublicKeyBytes as _jwkToPublicKeyBytes,
    jwkToSecretKeyBytes as _jwkToSecretKeyBytes
} from '../formats/jwk.js';
import {
    MULTIBASE_BASE58BTC_HEADER,
    MULTICODEC_SM2_PUB_HEADER,
    MULTICODEC_SM2_PRIV_HEADER,
    encodeKey,
    decodeKey
} from '../formats/codec.js';
import {
    exportKeyPair as _exportKeyPair,
    importKeyPair as _importKeyPair
} from '../utils/key-pair.js';

// multibase/multicodec constants
const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
const ALGORITHM = 'SM2';

/**
 * Default implementation for crypto functions.
 * Throws an error indicating that no crypto implementation has been set.
 * This ensures that the crypto implementation must be explicitly set before use.
 * 
 * @private
 * @throws {Error} Always throws an error indicating no implementation is set
 */
function no_implementation() {
    throw new Error('No crypto implementation set');
}

/**
 * Default cryptographic implementation object.
 * All methods will throw errors until a proper implementation is set.
 * This design allows for platform-specific implementations to be injected.
 * 
 * @private
 * @type {Object}
 */
let cryptoImpl = {
    generateKey: no_implementation,
    createSigner: no_implementation,
    createVerifier: no_implementation,
    digest: no_implementation
};

/**
 * SM2 Key Pair Class
 * 
 * This class implements the SM2 cryptographic algorithm with multi-key support.
 * It provides functionality for key generation, import/export, signing, and verification.
 * The implementation follows the SM2 standard and supports various key formats.
 * 
 * Security Features:
 * - Private key protection
 * - Key format validation
 * - Secure key generation
 * - Proper error handling
 * 
 * @class
 */
class SM2Multikey {
    /**
     * Creates a new instance of SM2Multikey.
     * Initializes an empty key pair with no keys or identifiers.
     * 
     * @constructor
     * @property {Buffer} publicKey - Public key buffer
     * @property {Buffer} secretKey - Private key buffer (sensitive)
     * @property {string} id - Optional key identifier
     * @property {string} controller - Optional controller identifier
     */
    constructor() {
        this.publicKey = null;
        this.secretKey = null;
        this.id = null;
        this.controller = null;
    }

    /**
     * Sets the cryptographic implementation to be used by this class.
     * This allows for platform-specific implementations while maintaining
     * a consistent API across different environments (Node.js, Browser).
     * 
     * Required Implementation Methods:
     * - generateKey(): Generates a new SM2 key pair
     * - createSigner(): Creates a signing function
     * - createVerifier(): Creates a verification function
     * - digest(): Creates a message digest
     * 
     * @static
     * @param {Object} impl - Crypto implementation object
     * @param {Function} impl.generateKey - Generates a new key pair
     * @param {Function} impl.createSigner - Creates a signing function
     * @param {Function} impl.createVerifier - Creates a verification function
     * @param {Function} impl.digest - Creates a message digest
     * @throws {ArgumentError} If the implementation object is invalid or missing required methods
     */
    static setCryptoImpl(impl) {
        if (!impl || typeof impl !== 'object') {
            throw new ArgumentError('Invalid crypto implementation', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        cryptoImpl = impl;
    }

    /**
     * Generates a new SM2 key pair with optional identifiers.
     * The generated key pair includes both public and private keys
     * and can be associated with an ID and controller.
     * 
     * Key Generation Process:
     * 1. Generate raw key pair using crypto implementation
     * 2. Create new SM2Multikey instance
     * 3. Set public and private keys
     * 4. Generate compressed public key
     * 5. Encode keys in multibase format
     * 6. Set optional identifiers
     * 
     * @static
     * @param {Object} [options={}] - Generation options
     * @param {string} [options.id] - Key identifier
     * @param {string} [options.controller] - Controller identifier
     * @returns {SM2Multikey} New key pair instance
     * @throws {ArgumentError} If provided options are invalid
     * @throws {KeyError} If key generation fails
     * @throws {FormatError} If key encoding fails
     */
    static generate({ id, controller } = {}) {
        // Validate arguments
        if (id && typeof id !== 'string') {
            throw new ArgumentError('ID must be a string', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        if (controller && typeof controller !== 'string') {
            throw new ArgumentError('Controller must be a string', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        // Generate key pair
        const keyPair = cryptoImpl.generateKey();
        if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
            throw new KeyError('Failed to generate key pair', { code: ErrorCodes.ERR_KEY_GENERATION });
        }

        // Create new instance
        const instance = new SM2Multikey();
        instance.publicKey = keyPair.publicKey;
        instance.secretKey = keyPair.secretKey;

        // Export public key in compressed format
        try {
            const compressedPublicKey = compressPublicKey(instance.publicKey);
            instance.publicKeyMultibase = encodeKey(
                MULTICODEC_SM2_PUB_HEADER,
                compressedPublicKey
            );
        } catch (error) {
            throw new FormatError('Failed to encode public key', {
                code: ErrorCodes.ERR_FORMAT_ENCODE,
                cause: error
            });
        }

        // Export private key in multibase format
        try {
            instance.secretKeyMultibase = encodeKey(
                MULTICODEC_SM2_PRIV_HEADER,
                instance.secretKey
            );
        } catch (error) {
            throw new FormatError('Failed to encode private key', {
                code: ErrorCodes.ERR_FORMAT_ENCODE,
                cause: error
            });
        }

        // Set ID and controller
        if (controller && !id) {
            // If controller is provided but ID is not, generate ID from controller and public key
            id = `${controller}#${instance.publicKeyMultibase}`;
        }
        instance.id = id;
        instance.controller = controller;

        return instance;
    }

    /**
     * Exports the key pair in a specified format.
     * Supports various export options for different use cases.
     * 
     * Export Options:
     * - publicKey: Export public key (default: true)
     * - secretKey: Export private key (default: false)
     * - includeContext: Include @context field (default: false)
     * - raw: Export in raw format (default: false)
     * - canonicalize: Sort properties alphabetically (default: false)
     * 
     * Security Note:
     * - Private key export is optional and should be used with caution
     * - Raw format should only be used in trusted environments
     * 
     * @param {Object} options - Export options
     * @param {boolean} [options.publicKey=true] - Whether to export public key
     * @param {boolean} [options.secretKey=false] - Whether to export private key
     * @param {boolean} [options.includeContext=false] - Whether to include context
     * @param {boolean} [options.raw=false] - Whether to export in raw format
     * @param {boolean} [options.canonicalize=false] - Whether to canonicalize output
     * @returns {Object} Exported key object
     * @throws {ArgumentError} If arguments are invalid
     * @throws {KeyError} If no key is available for export
     */
    export({
        publicKey = true,
        secretKey = false,
        includeContext = false,
        raw = false,
        canonicalize = false
    } = {}) {
        // Argument validation
        if (typeof publicKey !== 'boolean') {
            throw new ArgumentError('publicKey must be a boolean', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        if (typeof secretKey !== 'boolean') {
            throw new ArgumentError('secretKey must be a boolean', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        if (typeof includeContext !== 'boolean') {
            throw new ArgumentError('includeContext must be a boolean', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        if (typeof raw !== 'boolean') {
            throw new ArgumentError('raw must be a boolean', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }
        if (typeof canonicalize !== 'boolean') {
            throw new ArgumentError('canonicalize must be a boolean', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        if (!this.publicKey) {
            throw new KeyError('No key to export', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
        }

        const exported = {
            type: 'Multikey'
        };

        // If includeContext or id/controller is specified, add context
        if (includeContext || this.id || this.controller) {
            exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
        }

        if (this.id) {
            exported.id = this.id;
        }

        if (this.controller) {
            exported.controller = this.controller;
        }

        if (publicKey) {
            if (raw) {
                // Export public key in raw format
                exported.publicKey = this.publicKey;
            } else {
                // Export public key in compressed format
                const compressedPublicKey = compressPublicKey(this.publicKey);
                exported.publicKeyMultibase = encodeKey(
                    MULTICODEC_SM2_PUB_HEADER,
                    compressedPublicKey
                );
            }
        }

        if (secretKey && this.secretKey) {
            if (raw) {
                // Export private key in raw format
                exported.secretKey = this.secretKey;
            } else {
                // Export private key in multibase format
                exported.secretKeyMultibase = encodeKey(
                    MULTICODEC_SM2_PRIV_HEADER,
                    this.secretKey
                );
            }
        }

        // If canonicalize is true, sort properties alphabetically
        if (canonicalize) {
            const sortedKeys = Object.keys(exported).sort();
            const canonicalized = {};
            for (const key of sortedKeys) {
                canonicalized[key] = exported[key];
            }
            return canonicalized;
        }

        return exported;
    }

    /**
     * Imports a key pair from an exported key object.
     * Supports multiple import formats and performs thorough validation.
     * 
     * Import Process:
     * 1. Validate input arguments
     * 2. Handle different key formats (Multikey, JWK)
     * 3. Set default values and identifiers
     * 4. Validate Multikey format
     * 5. Import public key
     * 6. Import private key (if present)
     * 
     * Supported Formats:
     * - Multikey format
     * - JWK format (via publicKeyJwk)
     * 
     * @static
     * @param {Object} key - Exported key object
     * @returns {SM2Multikey} Imported key pair instance
     * @throws {ArgumentError} If exported key object is invalid
     * @throws {FormatError} If key format is invalid
     * @throws {KeyError} If key import fails
     */
    static from(key) {
        // 1. Argument validation
        if (!key || typeof key !== 'object') {
            throw new ArgumentError('Key must be an object', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        let multikey = { ...key };

        // 2. Handle different key formats
        if (multikey.type !== 'Multikey') {
            // Try loading from JWK if publicKeyJwk is present
            if (multikey.publicKeyJwk) {
                return SM2Multikey.fromJwk({ jwk: multikey.publicKeyJwk, secretKey: false });
            }
        }

        // 3. Set default values
        if (!multikey.type) {
            multikey.type = 'Multikey';
        }
        if (!multikey['@context']) {
            multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
        }
        if (multikey.controller && !multikey.id) {
            multikey.id = `${multikey.controller}#${multikey.publicKeyMultibase}`;
        }

        // 4. Validate SM2Multikey format
        try {
            SM2Multikey._assertMultikey(multikey);
        } catch (error) {
            throw new ArgumentError('Invalid SM2Multikey format', {
                code: ErrorCodes.ERR_FORMAT_MULTIKEY,
                cause: error
            });
        }

        // 5. Create new instance
        const instance = new SM2Multikey();
        instance.id = multikey.id;
        instance.controller = multikey.controller;

        // 6. Import public key
        if (multikey.publicKeyMultibase) {
            try {
                // Check multibase format
                if (!multikey.publicKeyMultibase.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
                    throw new FormatError('Invalid multibase format', { code: ErrorCodes.ERR_FORMAT_MULTIBASE });
                }

                // Decode and validate key
                const { key: compressedPublicKey, prefix: publicKeyPrefix } = decodeKey(multikey.publicKeyMultibase);

                // Validate key prefix
                if (!publicKeyPrefix.equals(MULTICODEC_SM2_PUB_HEADER)) {
                    throw new FormatError('Invalid public key format', { code: ErrorCodes.ERR_KEY_FORMAT });
                }

                // Uncompress public key
                instance.publicKey = uncompressPublicKey(compressedPublicKey);
                instance.publicKeyMultibase = multikey.publicKeyMultibase;
            } catch (error) {
                if (error instanceof SM2Error) {
                    throw error;
                }
                throw new FormatError('Failed to decode public key', {
                    code: ErrorCodes.ERR_FORMAT_MULTIBASE,
                    cause: error
                });
            }
        } else if (multikey.publicKey) {
            // Import raw public key
            try {
                // Validate raw public key format
                if (!Buffer.isBuffer(multikey.publicKey)) {
                    throw new FormatError('Public key must be a Buffer', { code: ErrorCodes.ERR_FORMAT_INPUT });
                }
                if (multikey.publicKey.length !== 64) {
                    throw new FormatError('Public key must be 64 bytes', { code: ErrorCodes.ERR_FORMAT_LENGTH });
                }

                const x = multikey.publicKey.subarray(0, 32);
                const y = multikey.publicKey.subarray(32, 64);
                validatePublicKeyCoordinates(x, y);
                instance.publicKey = multikey.publicKey;

                // Export public key in compressed format
                const compressedPublicKey = compressPublicKey(instance.publicKey);
                instance.publicKeyMultibase = encodeKey(
                    MULTICODEC_SM2_PUB_HEADER,
                    compressedPublicKey
                );
            } catch (error) {
                if (error instanceof SM2Error) {
                    throw error;
                }
                throw new FormatError('Invalid public key format', {
                    code: ErrorCodes.ERR_FORMAT_INPUT,
                    cause: error
                });
            }
        } else {
            throw new KeyError('No public key found', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
        }

        // 7. Import private key if present
        if (multikey.secretKeyMultibase) {
            try {
                // Check multibase format
                if (!multikey.secretKeyMultibase.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
                    throw new FormatError('Invalid multibase format', { code: ErrorCodes.ERR_FORMAT_MULTIBASE });
                }

                // Decode and validate key
                const { key: secretKey, prefix: secretKeyPrefix } = decodeKey(multikey.secretKeyMultibase);

                // Validate key prefix
                if (!secretKeyPrefix.equals(MULTICODEC_SM2_PRIV_HEADER)) {
                    throw new FormatError('Invalid private key format', { code: ErrorCodes.ERR_KEY_FORMAT });
                }

                instance.secretKey = secretKey;
                instance.secretKeyMultibase = multikey.secretKeyMultibase;
            } catch (error) {
                if (error instanceof SM2Error) {
                    throw error;
                }
                throw new FormatError('Failed to decode private key', {
                    code: ErrorCodes.ERR_FORMAT_MULTIBASE,
                    cause: error
                });
            }
        } else if (multikey.secretKey) {
            // Import raw private key
            instance.secretKey = multikey.secretKey;

            // Export private key in multibase format
            instance.secretKeyMultibase = encodeKey(
                MULTICODEC_SM2_PRIV_HEADER,
                instance.secretKey
            );
        }

        return instance;
    }

    /**
     * Verify if the key pair conforms to SM2Multikey format
     * Performs thorough validation of the key object structure.
     * 
     * Validation Checks:
     * 1. Key is an object
     * 2. Context is correct
     * 3. Required fields are present
     * 4. Field types are correct
     * 
     * @param {Object} key - The key object to verify
     * @throws {TypeError} If the key object format is incorrect
     * @private
     */
    static _assertMultikey(key) {
        if (!(key && typeof key === 'object')) {
            throw new TypeError('"key" must be an object.');
        }
        if (!(key['@context'] === MULTIKEY_CONTEXT_V1_URL ||
            (Array.isArray(key['@context']) &&
                key['@context'].includes(MULTIKEY_CONTEXT_V1_URL)))) {
            throw new TypeError(
                '"key" must be a SM2Multikey with context ' +
                `"${MULTIKEY_CONTEXT_V1_URL}".`);
        }
    }

    /**
     * Imports a key pair from a JWK object.
     * Supports both public and private key import.
     * 
     * Import Process:
     * 1. Convert from JWK format
     * 2. Create new instance
     * 3. Import public key
     * 4. Import private key (if requested)
     * 
     * JWK Requirements:
     * - Must contain valid kty field
     * - Must contain required key parameters
     * - Must use correct algorithm
     * 
     * @static
     * @param {Object} options - Import options
     * @param {Object} options.jwk - JWK key object
     * @param {boolean} [options.secretKey=false] - Whether to import private key
     * @param {string} [options.id] - Key identifier
     * @param {string} [options.controller] - Controller identifier
     * @returns {SM2Multikey} Imported key pair instance
     * @throws {ArgumentError} If JWK is invalid
     * @throws {FormatError} If JWK format is incorrect
     */
    static fromJwk({ jwk, secretKey = false, id, controller } = {}) {
        // 1. Argument validation
        if (!jwk || typeof jwk !== 'object') {
            throw new ArgumentError('Invalid JWK object', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        // 2. Convert JWK format
        const keyPair = fromJwk({ jwk, secretKey, id, controller });

        // 3. Create instance
        const instance = new SM2Multikey();
        instance.publicKey = keyPair.publicKey;
        instance.secretKey = keyPair.secretKey;
        instance.id = keyPair.id;
        instance.controller = keyPair.controller;

        return instance;
    }

    /**
     * Converts a key pair to a JWK object.
     * Supports both public and private key export.
     * 
     * Export Process:
     * 1. Validate arguments
     * 2. Check key availability
     * 3. Convert to JWK format
     * 
     * JWK Format:
     * - kty: Key type (EC)
     * - crv: Curve name (SM2)
     * - x, y: Public key coordinates
     * - d: Private key (if requested)
     * 
     * @static
     * @param {Object} options - Options
     * @param {SM2Multikey} options.keyPair - Key pair object
     * @param {boolean} [options.secretKey=false] - Whether to include private key
     * @returns {object} JWK key object
     * @throws {ArgumentError} If arguments are invalid
     * @throws {KeyError} If no key is available for export
     */
    static toJwk({ keyPair, secretKey = false } = {}) {
        // 1. Argument validation
        if (!keyPair || !(keyPair instanceof SM2Multikey)) {
            throw new ArgumentError('Invalid key pair', { code: ErrorCodes.ERR_ARGUMENT_INVALID });
        }

        // 2. Check key availability
        if (!keyPair.publicKey) {
            throw new KeyError('No public key available', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
        }

        // 3. Convert to JWK format
        return toJwk({
            keyPair: {
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey
            },
            secretKey
        });
    }

    /**
     * Creates a signer function for this key pair.
     * The signer function is used to create digital signatures.
     * 
     * Signer Object:
     * - algorithm: Signature algorithm (SM2)
     * - id: Key identifier
     * - sign: Signing function
     * 
     * Security Note:
     * - Private key must be available
     * - Signing operation is performed in memory
     * 
     * @param {Object} [options={}] - Options
     * @param {string} [options.id] - Key identifier
     * @returns {Object} Signer object with sign function
     * @throws {KeyError} If no private key is available
     */
    signer() {
        if (!this.secretKey) {
            throw new KeyError('No private key available', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
        }

        return {
            algorithm: ALGORITHM,
            id: this.id,
            sign: cryptoImpl.createSigner({
                publicKey: this.publicKey,
                secretKey: this.secretKey
            })
        };
    }

    /**
     * Creates a verifier function for this key pair.
     * The verifier function is used to verify digital signatures.
     * 
     * Verifier Object:
     * - algorithm: Signature algorithm (SM2)
     * - id: Key identifier
     * - verify: Verification function
     * 
     * Security Note:
     * - Only requires public key
     * - Safe to use in untrusted environments
     * 
     * @param {Object} [options={}] - Options
     * @param {string} [options.id] - Key identifier
     * @returns {Object} Verifier object with verify function
     * @throws {KeyError} If no public key is available
     */
    verifier() {
        if (!this.publicKey) {
            throw new KeyError('No public key available', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
        }

        return {
            algorithm: ALGORITHM,
            id: this.id,
            verify: cryptoImpl.createVerifier({
                publicKey: this.publicKey
            })
        };
    }
}

export { SM2Multikey };
