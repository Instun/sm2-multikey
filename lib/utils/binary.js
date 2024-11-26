/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Binary Data Type Conversion Utilities
 * 
 * This module provides utilities for handling and converting between different
 * binary data types (Buffer and Uint8Array) in a cross-platform compatible way.
 * It is designed to work seamlessly in both Node.js and browser environments,
 * ensuring consistent binary data handling across platforms.
 * 
 * Key Features:
 * - Type validation for binary data
 * - Zero-copy conversion between Buffer and Uint8Array when possible
 * - Consistent error handling with detailed messages
 * - Platform-agnostic implementation
 * 
 * Implementation Notes:
 * - Preserves data integrity during conversion
 * - Handles platform-specific type differences
 * - Provides clear error messages with error codes
 * - Optimizes memory usage by avoiding unnecessary copies
 * 
 * Performance Considerations:
 * - Uses zero-copy operations when possible
 * - Avoids unnecessary type conversions
 * - Performs validation checks before operations
 * 
 * Security Considerations:
 * - Validates input types to prevent type confusion attacks
 * - Throws typed errors for proper error handling
 * - Maintains data integrity during conversions
 * 
 * Common Use Cases:
 * - Cryptographic operations requiring specific binary formats
 * - Cross-platform data handling
 * - Network protocol implementations
 * - Binary file processing
 * 
 * @module utils/binary-utils
 */

import { ArgumentError, ErrorCodes } from '../core/errors.js';

/**
 * Check if the input is valid binary data (Buffer or Uint8Array)
 * 
 * This function validates that the input data is either a Buffer or
 * Uint8Array, which are the two main binary data types used across
 * Node.js and browser environments. It performs a type check using
 * both Buffer.isBuffer and instanceof Uint8Array to ensure compatibility
 * with various JavaScript environments.
 * 
 * Performance Note:
 * - This is a lightweight operation with minimal overhead
 * - Should be used before performing binary operations
 * 
 * @param {any} data - Data to validate
 * @returns {boolean} True if data is Buffer or Uint8Array
 * @throws {never} This function never throws
 * 
 * @example
 * // Basic validation
 * if (!isValidBinaryData(input)) {
 *   throw new Error('Invalid binary data');
 * }
 * 
 * @example
 * // Use in parameter validation
 * function processData(data) {
 *   if (!isValidBinaryData(data)) {
 *     throw new ArgumentError('Data must be Buffer or Uint8Array');
 *   }
 *   // Process data...
 * }
 */
export function isValidBinaryData(data) {
  return Buffer.isBuffer(data) || data instanceof Uint8Array;
}

/**
 * Convert input data to Buffer
 * 
 * This function ensures the input data is converted to a Buffer,
 * handling both Buffer and Uint8Array inputs. If the input is
 * already a Buffer, it is returned as-is to avoid unnecessary
 * conversion. This is particularly useful when working with Node.js
 * APIs that expect Buffer inputs.
 * 
 * Performance Notes:
 * - Zero-copy if input is already a Buffer
 * - Single copy when converting from Uint8Array
 * - Validates input type before conversion
 * 
 * @param {Buffer|Uint8Array} data - Binary data to convert
 * @returns {Buffer} Data as Buffer
 * @throws {ArgumentError} If input is not valid binary data
 * 
 * @example
 * // Convert Uint8Array to Buffer
 * const uint8Array = new Uint8Array([1, 2, 3]);
 * const buffer = toBuffer(uint8Array);
 * console.log(buffer); // <Buffer 01 02 03>
 * 
 * @example
 * // Pass-through existing Buffer
 * const existingBuffer = Buffer.from([4, 5, 6]);
 * const sameBuffer = toBuffer(existingBuffer);
 * console.log(sameBuffer === existingBuffer); // true
 */
export function toBuffer(data) {
  if (!isValidBinaryData(data)) {
    throw new ArgumentError('Invalid binary data type', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Data must be Buffer or Uint8Array'
    });
  }
  
  return Buffer.isBuffer(data) ? data : Buffer.from(data);
}

/**
 * Convert input data to Uint8Array
 * 
 * This function ensures the input data is converted to a Uint8Array,
 * handling both Buffer and Uint8Array inputs. If the input is already
 * a Uint8Array, it is returned as-is to avoid unnecessary conversion.
 * This is particularly useful when working with Web APIs or when
 * cross-platform compatibility is required.
 * 
 * Performance Notes:
 * - Zero-copy if input is already a Uint8Array
 * - Single copy when converting from Buffer
 * - Special handling for Buffer to preserve memory efficiency
 * 
 * Implementation Details:
 * - For Buffer inputs, creates a new Uint8Array view
 * - For Uint8Array inputs, returns the original
 * - Validates input type before conversion
 * 
 * @param {Buffer|Uint8Array} data - Binary data to convert
 * @returns {Uint8Array} Data as Uint8Array
 * @throws {ArgumentError} If input is not valid binary data
 * 
 * @example
 * // Convert Buffer to Uint8Array
 * const buffer = Buffer.from([1, 2, 3]);
 * const uint8Array = toUint8Array(buffer);
 * console.log(uint8Array); // Uint8Array [1, 2, 3]
 * 
 * @example
 * // Pass-through existing Uint8Array
 * const existingArray = new Uint8Array([4, 5, 6]);
 * const sameArray = toUint8Array(existingArray);
 * console.log(sameArray === existingArray); // true
 */
export function toUint8Array(data) {
  if (!isValidBinaryData(data)) {
    throw new ArgumentError('Invalid binary data type', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Data must be Buffer or Uint8Array'
    });
  }
  
  if (data instanceof Uint8Array) {
    // If it's a Buffer, we need to create a new Uint8Array
    // If it's a regular Uint8Array, return as-is
    return Buffer.isBuffer(data) ? new Uint8Array(data) : data;
  }
  
  return new Uint8Array(data);
}

/**
 * Create a new binary data instance of the same type as the template
 * 
 * This function creates a new binary data instance (Buffer or Uint8Array)
 * matching the type of the template parameter. This is useful when you
 * need to ensure consistent return types in functions, particularly in
 * cryptographic operations where maintaining type consistency is important.
 * 
 * Performance Notes:
 * - May require a copy operation if types don't match
 * - Validates both inputs before conversion
 * - Uses optimized conversion methods internally
 * 
 * Use Cases:
 * - Maintaining consistent types in cryptographic operations
 * - Ensuring API return type consistency
 * - Cross-platform data handling
 * 
 * @param {Buffer|Uint8Array} template - Template to match type
 * @param {Buffer|Uint8Array} data - Data to convert
 * @returns {Buffer|Uint8Array} Converted data matching template type
 * @throws {ArgumentError} If either input is not valid binary data
 * 
 * @example
 * // Match return type to input type
 * function processData(input) {
 *   const result = someOperation();
 *   return matchBinaryType(input, result);
 * }
 * 
 * @example
 * // Convert between types
 * const buffer = Buffer.from([1, 2, 3]);
 * const template = new Uint8Array([4, 5, 6]);
 * const result = matchBinaryType(template, buffer);
 * console.log(result instanceof Uint8Array); // true
 */
export function matchBinaryType(template, data) {
  if (!isValidBinaryData(template) || !isValidBinaryData(data)) {
    throw new ArgumentError('Invalid binary data type', {
      code: ErrorCodes.ERR_ARGUMENT_INVALID,
      details: 'Both template and data must be Buffer or Uint8Array'
    });
  }
  
  return Buffer.isBuffer(template) ? toBuffer(data) : toUint8Array(data);
}
