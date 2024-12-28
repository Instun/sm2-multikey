# SM2 Multikey Library

A comprehensive implementation of the SM2 cryptographic algorithm with multikey support, designed for both Node.js and browser environments.

## Overview

The SM2 Multikey library provides a complete implementation of the SM2 cryptographic algorithm with support for the W3C Multikey format. It is specifically designed for:

- **Key Management**: Handle SM2 key pairs in multiple formats
- **Digital Signatures**: Generate and verify SM2 signatures with SM3 digest
- **Cross-Platform**: Consistent API across Node.js and browser environments

The library implements a pluggable architecture that allows for platform-specific optimizations while maintaining a consistent API. In Node.js environments, it leverages native crypto implementations for optimal performance, while in browsers it uses a pure JavaScript implementation.

## Features

### Cryptographic Operations
- SM2 key pair generation with secure defaults
- Digital signature creation and verification
- SM3 message digest calculation
- Support for compressed public keys

### Key Management
- Multiple key format support:
  - JSON Web Key (JWK)
  - W3C Multikey format
  - Support for key compression
- Secure key import/export operations
- Key format validation and error handling

### Security
- Memory-safe key operations
- Protected private key handling
- Comprehensive input validation
- Proper error handling

## Standards Compliance

### Cryptographic Standards
- **GB/T 32918.1-2016**: SM2 Elliptic Curve Cryptography
  - Key generation and management
  - Digital signature algorithms
  - Public key encryption
- **GB/T 32905-2016**: SM3 Cryptographic Hash Algorithm
  - Message digest calculation
  - Data integrity verification

## Installation

```bash
npm install @instun/sm2-multikey
```

## Usage

### Basic Key Operations

```javascript
import { SM2Multikey } from '@instun/sm2-multikey';

// Generate a new key pair
const key = await SM2Multikey.generate({
  controller: 'did:example:123'
});

// Create and verify signatures
const signer = key.signer();
const signature = await signer.sign({ data });
const isValid = await key.verifier().verify({ data, signature });
```

### Key Export/Import

```javascript
// Export key
const exported = key.export({
  publicKey: true,
  secretKey: false,
  includeContext: true
});

// Import from JWK
const imported = SM2Multikey.fromJwk({
  jwk,
  id: 'key-1',
  controller: 'did:example:123'
});
```

## Platform Requirements

- Node.js 16.x or later
- OpenSSL 1.1.1 or later with SM2 support
- Modern browsers with ES6+ support

## Security Features

- Protected private key operations
- Key format validation
- Secure key generation
- Proper error handling

## API Documentation

### SM2Multikey Class

Core class for SM2 key pair operations.

#### Static Methods

##### generate(options)
Creates a new SM2 key pair.
- **Parameters:**
  - `options` (Object, optional)
    - `id` (string): Key identifier
    - `controller` (string): Controller identifier
- **Returns:** SM2Multikey instance
- **Throws:** 
  - `ArgumentError`: If options are invalid
  - `KeyError`: If key generation fails
  - `FormatError`: If key encoding fails

##### from(key)
Imports a key from Multikey format.
- **Parameters:**
  - `key` (Object): Multikey formatted key data
- **Returns:** SM2Multikey instance
- **Throws:**
  - `ArgumentError`: If key object is invalid
  - `FormatError`: If key format is invalid

##### fromJwk(options)
Imports a key from JWK format.
- **Parameters:**
  - `options` (Object)
    - `jwk` (Object): JWK key data
    - `secretKey` (boolean, optional): Whether to import private key
    - `id` (string, optional): Key identifier
    - `controller` (string, optional): Controller identifier
- **Returns:** SM2Multikey instance
- **Throws:**
  - `ArgumentError`: If JWK is invalid
  - `FormatError`: If JWK format is incorrect

#### Instance Methods

##### export(options)
Exports the key pair in specified format.
- **Parameters:**
  - `options` (Object, optional)
    - `publicKey` (boolean): Export public key (default: true)
    - `secretKey` (boolean): Export private key (default: false)
    - `includeContext` (boolean): Include @context field (default: false)
    - `raw` (boolean): Export in raw format (default: false)
    - `canonicalize` (boolean): Sort properties (default: false)
- **Returns:** Exported key object
- **Throws:**
  - `ArgumentError`: If options are invalid
  - `KeyError`: If required key is not available

##### signer()
Creates a signing function for this key pair.
- **Returns:** Object with properties:
  - `algorithm` (string): 'SM2'
  - `id` (string): Key identifier
  - `sign` (Function): Signing function
    - Parameters:
      - `data` (Buffer|Uint8Array): Data to sign
    - Returns: Promise<Buffer> Signature
- **Throws:** `KeyError` if private key is not available

##### verifier()
Creates a verification function for this key pair.
- **Returns:** Object with properties:
  - `algorithm` (string): 'SM2'
  - `id` (string): Key identifier
  - `verify` (Function): Verification function
    - Parameters:
      - `data` (Buffer|Uint8Array): Original data
      - `signature` (Buffer|Uint8Array): Signature to verify
    - Returns: Promise<boolean> Verification result
- **Throws:** `KeyError` if public key is not available

### Error Types

The library provides several error types for specific failure cases:

#### ArgumentError
Thrown when an invalid argument is provided.
- Properties:
  - `message`: Error description
  - `code`: Error code (ERR_ARGUMENT_INVALID)
  - `argument`: Name of the invalid argument

#### KeyError
Thrown when a key operation fails.
- Properties:
  - `message`: Error description
  - `code`: Error code (ERR_KEY_*)
  - `operation`: Failed operation name

#### FormatError
Thrown when a format conversion fails.
- Properties:
  - `message`: Error description
  - `code`: Error code (ERR_FORMAT_*)
  - `format`: Name of the problematic format

#### SM2Error
Base class for SM2-specific errors.
- Properties:
  - `message`: Error description
  - `code`: Error code
  - `cause`: Original error (if any)

Each error includes:
- Descriptive error message
- Specific error code for programmatic handling
- Original error cause when applicable
- Additional context-specific properties

## License

Copyright (c) 2024 Instun, Inc. All rights reserved.