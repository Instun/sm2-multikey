/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview DER (Distinguished Encoding Rules) Format Handling
 * 
 * This module implements the DER encoding rules as specified in ITU-T X.690,
 * with specific focus on SM2 cryptographic data structures. DER is a restricted
 * variant of BER that ensures canonical encoding for each value, making it
 * suitable for cryptographic applications.
 * 
 * Key Features:
 * - ASN.1 type encoding/decoding
 * - Strict DER compliance
 * - Zero-copy operations
 * - Input format flexibility
 * - Type-preserving output
 * 
 * Security Considerations:
 * - Strict DER validation
 * - Length field verification
 * - Buffer overflow protection
 * - ASN.1 type checking
 * - Memory safety
 * 
 * Performance Notes:
 * - Zero-copy operations
 * - Minimal allocations
 * - Early validation
 * - Efficient buffering
 * - Type preservation
 * 
 * DER Format Structure:
 * ```
 * | Type | Length | Value |
 * |------|---------|-------|
 * | Tag  | Size    | Data  |
 * | 1B   | 1-5B    | nB    |
 * ```
 * 
 * Standards Compliance:
 * - ITU-T X.690: DER Encoding Rules
 * - ITU-T X.680: ASN.1 Notation
 * - RFC 5280: X.509 Certificate Format
 * - GM/T 0009-2012: SM2 Digital Signature
 * - GM/T 0010-2012: SM2 Public Key Format
 * 
 * Usage Example:
 * ```javascript
 * import { encodeDERSequence, encodeDERLength } from './der.js';
 * 
 * // Create a DER sequence
 * const sequence = encodeDERSequence([
 *   // SM2 signature (r,s) values
 *   encodeDERInteger(r),
 *   encodeDERInteger(s)
 * ]);
 * 
 * // Parse DER length
 * const [length, offset] = readDERLength(sequence, 0);
 * console.log('Sequence length:', length);
 * ```
 * 
 * @module formats/der
 * @see {@link https://www.itu.int/rec/T-REC-X.690/|X.690 Specification}
 * @see {@link https://www.itu.int/rec/T-REC-X.680/|X.680 Specification}
 */

import { FormatError, ErrorCodes } from '../core/errors.js';
import { isValidBinaryData, toBuffer, matchBinaryType } from '../utils/binary.js';

/**
 * ASN.1 type tags used in DER encoding
 * 
 * These tags identify the type of data being encoded according to
 * ASN.1 (Abstract Syntax Notation One) X.680 specification. Each
 * tag has specific encoding rules and constraints.
 * 
 * Tag Structure:
 * ```
 * |Class|P/C|  Tag Number  |
 * | 0 0 | 0 | x x x x x |
 * ```
 * 
 * Tag Classes:
 * - Universal (00): Standard ASN.1 types
 * - Application (01): Application-specific
 * - Context-specific (10): Context-dependent
 * - Private (11): Private use
 * 
 * @enum {number}
 * @readonly
 */
export const ASN1 = {
  /** 
   * Universal type for sequences (0x30)
   * Used for ordered collections of values
   */
  SEQUENCE: 0x30,
  
  /** 
   * Universal type for integers (0x02)
   * Used for arbitrary precision integers
   */
  INTEGER: 0x02,
  
  /** 
   * Universal type for octet strings (0x04)
   * Used for arbitrary byte sequences
   */
  OCTET_STRING: 0x04,
  
  /** 
   * Universal type for object identifiers (0x06)
   * Used for OID values like algorithm IDs
   */
  OBJECT_IDENTIFIER: 0x06,
  
  /** 
   * Context-specific type (0xa1)
   * Used for application-dependent values
   */
  CONTEXT_SPECIFIC: 0xa1,
  
  /** 
   * Universal type for bit strings (0x03)
   * Used for arbitrary bit sequences
   */
  BIT_STRING: 0x03,
};

/**
 * Read and decode a DER length field
 * 
 * This function implements the DER length field decoding rules from X.690,
 * supporting both short and long form encodings. It performs strict validation
 * to ensure compliance and security.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Initial byte analysis
 * 3. Length field decoding
 * 4. Minimal encoding check
 * 5. Range validation
 * 
 * Security Considerations:
 * - Strict format validation
 * - Integer overflow protection
 * - Buffer bounds checking
 * - Minimal encoding enforcement
 * - Memory safety checks
 * 
 * Performance Notes:
 * - Early validation failures
 * - Zero-copy operations
 * - Minimal allocations
 * - Efficient bit operations
 * - Type preservation
 * 
 * Length Field Format:
 * ```
 * Short form (0-127):
 * | 0 | Length Value |
 * | 0 | x x x x x x x |
 * 
 * Long form (>=128):
 * | 1 | Byte Count | Length Bytes |
 * | 1 | n n n n n n n | n bytes |
 * ```
 * 
 * @param {Buffer|Uint8Array} data - DER encoded data
 * @param {number} offset - Starting offset in data
 * @returns {[number, number]} Tuple of [length value, new offset]
 * @throws {FormatError} If length encoding is invalid
 * 
 * @example
 * ```javascript
 * // Read a DER length field
 * const buffer = Buffer.from([0x82, 0x02, 0x7F]); // 639 in long form
 * const [length, newOffset] = readDERLength(buffer, 0);
 * console.log(length);     // 639
 * console.log(newOffset);  // 3
 * 
 * // Handle short form
 * const short = Buffer.from([0x7F]); // 127 in short form
 * const [len, off] = readDERLength(short, 0);
 * console.log(len);  // 127
 * console.log(off);  // 1
 * ```
 */
export function readDERLength(data, offset) {
  if (!isValidBinaryData(data)) {
    throw new FormatError('Input must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (typeof offset !== 'number' || offset < 0) {
    throw new FormatError('Invalid offset', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  // Convert to Buffer for consistent byte access
  const buffer = toBuffer(data);

  if (offset >= buffer.length) {
    throw new FormatError('Invalid DER length offset', { code: ErrorCodes.ERR_FORMAT_LENGTH });
  }

  const firstByte = buffer[offset++];
  if (firstByte < 0x80) {
    return [firstByte, offset];
  }

  const lenBytes = firstByte & 0x7f;
  if (lenBytes === 0 || offset + lenBytes > buffer.length) {
    throw new FormatError('Invalid DER length encoding', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  let length = 0;
  for (let i = 0; i < lenBytes; i++) {
    length = (length << 8) | buffer[offset++];
    if (length > 0x7fffffff) {
      throw new FormatError('DER length too large', { code: ErrorCodes.ERR_FORMAT_LENGTH });
    }
  }

  if (length <= 0x7f) {
    throw new FormatError('Non-minimal DER length encoding', { code: ErrorCodes.ERR_FORMAT_INVALID });
  }

  return [length, offset];
}

/**
 * Encode a length value in DER format
 * 
 * This function implements the DER length field encoding rules from X.690,
 * automatically selecting between short and long form based on the value.
 * It ensures minimal encoding and strict DER compliance.
 * 
 * Processing Steps:
 * 1. Value validation
 * 2. Form selection
 * 3. Byte encoding
 * 4. Type matching
 * 
 * Security Considerations:
 * - Range validation
 * - Integer overflow protection
 * - Type safety checks
 * - Memory bounds checking
 * - Safe allocation
 * 
 * Performance Notes:
 * - Minimal allocations
 * - Efficient encoding
 * - Zero-copy operations
 * - Type preservation
 * - Early validation
 * 
 * Encoding Format:
 * ```
 * Short form (0-127):
 * | 0xxxxxxx | Single byte value
 * 
 * Long form (>=128):
 * | 1nnnnnnn | Length bytes |
 * | Count    | Big-endian value |
 * ```
 * 
 * @param {number} length - Length value to encode
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} DER encoded length field
 * @throws {FormatError} If length value is invalid
 * 
 * @example
 * ```javascript
 * // Encode short form length
 * const short = encodeDERLength(127);
 * console.log(short);  // <Buffer 7F>
 * 
 * // Encode long form length
 * const long = encodeDERLength(639);
 * console.log(long);   // <Buffer 82 02 7F>
 * 
 * // Match output type
 * const uint8 = new Uint8Array(1);
 * const matched = encodeDERLength(127, uint8);
 * console.log(matched instanceof Uint8Array);  // true
 * ```
 */
export function encodeDERLength(length, outputType) {
  if (typeof length !== 'number' || length < 0 || length > 0x7fffffff) {
    throw new FormatError('Invalid length value', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  let result;
  if (length < 0x80) {
    result = Buffer.from([length]);
  } else {
    const bytes = [];
    let temp = length;
    while (temp > 0) {
      bytes.unshift(temp & 0xff);
      temp >>= 8;
    }
    bytes.unshift(0x80 | bytes.length);
    result = Buffer.from(bytes);
  }

  return outputType ? matchBinaryType(outputType, result) : result;
}

/**
 * Encode a sequence of items in DER format
 * 
 * This function implements the DER sequence encoding rules from X.690,
 * creating a properly formatted SEQUENCE type with the provided items.
 * It ensures proper ordering and type consistency.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. Item conversion
 * 3. Length calculation
 * 4. Sequence assembly
 * 5. Type matching
 * 
 * Security Considerations:
 * - Type validation
 * - Length verification
 * - Memory safety
 * - Buffer overflow protection
 * - Safe concatenation
 * 
 * Performance Notes:
 * - Minimal copying
 * - Efficient assembly
 * - Pre-allocation
 * - Type preservation
 * - Early validation
 * 
 * Sequence Format:
 * ```
 * | Tag    | Length | Value           |
 * | 0x30   | DER    | Encoded Items   |
 * | 1 byte | 1-5B   | Concatenated    |
 * ```
 * 
 * @param {(Buffer|Uint8Array)[]} items - Array of pre-encoded items
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} DER encoded sequence
 * @throws {FormatError} If items array or any item is invalid
 * 
 * @example
 * ```javascript
 * // Create a DER sequence for SM2 signature
 * const sequence = encodeDERSequence([
 *   encodeDERInteger(r),    // r value
 *   encodeDERInteger(s)     // s value
 * ]);
 * 
 * // Create a sequence with type matching
 * const uint8 = new Uint8Array();
 * const typed = encodeDERSequence([
 *   encodeDERInteger(123),
 *   encodeDERString('test')
 * ], uint8);
 * ```
 */
export function encodeDERSequence(items, outputType) {
  if (!Array.isArray(items)) {
    throw new FormatError('Items must be an array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  // Convert all items to Buffer and calculate total length
  const buffers = items.map(item => {
    if (!isValidBinaryData(item)) {
      throw new FormatError('Each item must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
    }
    return toBuffer(item);
  });

  const totalLength = buffers.reduce((sum, buf) => sum + buf.length, 0);
  const lengthField = encodeDERLength(totalLength);

  // Combine all parts
  const result = Buffer.concat([
    Buffer.from([ASN1.SEQUENCE]),
    lengthField,
    ...buffers
  ]);

  return outputType ? matchBinaryType(outputType, result) : result;
}

/**
 * Encode an Object Identifier in DER format
 * 
 * This function implements the DER object identifier encoding rules from
 * X.690, creating a properly formatted OBJECT IDENTIFIER type. It handles
 * the specific encoding rules for OID components.
 * 
 * Processing Steps:
 * 1. Input validation
 * 2. OID verification
 * 3. Length encoding
 * 4. Value assembly
 * 5. Type matching
 * 
 * Security Considerations:
 * - OID validation
 * - Length verification
 * - Buffer safety
 * - Type checking
 * - Safe concatenation
 * 
 * Performance Notes:
 * - Zero-copy when possible
 * - Minimal allocations
 * - Efficient assembly
 * - Type preservation
 * - Early validation
 * 
 * OID Format:
 * ```
 * | Tag    | Length | Value    |
 * | 0x06   | DER    | OID Data |
 * | 1 byte | 1-5B   | n bytes  |
 * ```
 * 
 * @param {Buffer|Uint8Array} oid - Pre-encoded OID value
 * @param {Buffer|Uint8Array} [outputType] - Optional type to match output format
 * @returns {Buffer|Uint8Array} DER encoded OID
 * @throws {FormatError} If OID is invalid
 * 
 * @example
 * ```javascript
 * // Encode an OID for SM2 signature
 * const oid = Buffer.from([0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75]);
 * const encoded = encodeDEROID(oid);
 * 
 * // Encode with type matching
 * const uint8 = new Uint8Array();
 * const typed = encodeDEROID(oid, uint8);
 * console.log(typed instanceof Uint8Array);  // true
 * ```
 */
export function encodeDEROID(oid, outputType) {
  if (!isValidBinaryData(oid)) {
    throw new FormatError('OID must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  if (outputType && !isValidBinaryData(outputType)) {
    throw new FormatError('Output type must be a Buffer or Uint8Array', { code: ErrorCodes.ERR_FORMAT_INPUT });
  }

  const oidBuf = toBuffer(oid);
  const lengthField = encodeDERLength(oidBuf.length);

  const result = Buffer.concat([
    Buffer.from([ASN1.OBJECT_IDENTIFIER]),
    lengthField,
    oidBuf
  ]);

  return outputType ? matchBinaryType(outputType, result) : result;
}
