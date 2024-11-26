/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

/**
 * @fileoverview Error Handling System for SM2 Cryptographic Operations
 * 
 * This module provides a comprehensive error handling system for the SM2
 * cryptographic library. It implements a hierarchy of error classes and
 * utilities for consistent error creation and formatting.
 * 
 * Key Features:
 * - Hierarchical error classes for different types of operations
 * - Standardized error codes and messages
 * - Support for error chaining with cause tracking
 * - Detailed error information with optional parameters
 * 
 * Error Categories:
 * - Argument validation errors
 * - Format and encoding errors
 * - Key management errors
 * - Signature operation errors
 * - Verification process errors
 * - Import/Export operation errors
 * - State management errors
 * 
 * Security Considerations:
 * - Error messages avoid exposing sensitive information
 * - Consistent error handling across operations
 * - Proper error propagation and cause tracking
 * - Secure error recovery mechanisms
 * 
 * Performance Considerations:
 * - Efficient error object creation
 * - Minimal memory footprint
 * - Optimized error message formatting
 * - Lazy parameter evaluation
 * 
 * Best Practices:
 * 1. Always use appropriate error types for different scenarios
 * 2. Include relevant context in error messages
 * 3. Chain errors to preserve the original cause
 * 4. Handle errors at appropriate levels
 * 5. Log errors with sufficient detail for debugging
 * 6. Avoid exposing sensitive information in errors
 * 
 * Usage Examples:
 * ```javascript
 * // Basic error creation
 * throw new KeyError('Invalid key format');
 * 
 * // Error with additional context
 * throw new FormatError('Invalid encoding', {
 *   code: ErrorCodes.ERR_FORMAT_ENCODE,
 *   encoding: 'base58'
 * });
 * 
 * // Error chaining
 * try {
 *   // ... some operation
 * } catch (error) {
 *   throw createError(
 *     ErrorCodes.ERR_KEY_INVALID,
 *     { keyId: 'abc123' },
 *     error
 *   );
 * }
 * 
 * // Error with formatted message
 * const msg = formatErrorMessage(
 *   'Invalid key type: {type}',
 *   { type: 'RSA' }
 * );
 * 
 * // Complete error handling example
 * try {
 *   const key = await importKey(data);
 * } catch (error) {
 *   if (error instanceof FormatError) {
 *     // Handle format errors
 *     console.error('Invalid key format:', error.message);
 *   } else if (error instanceof KeyError) {
 *     // Handle key errors
 *     console.error('Key operation failed:', error.message);
 *   } else {
 *     // Handle other errors
 *     console.error('Unexpected error:', error);
 *   }
 * }
 * ```
 * 
 * Error Recovery Strategies:
 * 1. Validation Errors
 *    - Retry with corrected input
 *    - Provide feedback to user
 *    - Log validation failures
 * 
 * 2. Format Errors
 *    - Attempt format conversion
 *    - Try alternative formats
 *    - Request correct format
 * 
 * 3. Key Errors
 *    - Attempt key regeneration
 *    - Use backup keys
 *    - Request new keys
 * 
 * 4. Operation Errors
 *    - Retry with backoff
 *    - Use alternative methods
 *    - Fail gracefully
 * 
 * Related Standards:
 * - Error Handling Best Practices (RFC 7807)
 * - Cryptographic Error Reporting
 * - Security Considerations (RFC 3552)
 * 
 * @module errors
 */

/**
 * Base error class for all SM2 cryptographic operations
 * 
 * This class extends the native Error class and adds support for:
 * - Error codes for programmatic handling
 * - Error cause tracking for debugging
 * - Consistent error message formatting
 * 
 * Best Practices:
 * 1. Always include a descriptive message
 * 2. Use appropriate error codes
 * 3. Chain errors when appropriate
 * 4. Include relevant context
 * 
 * @class
 * @extends Error
 */
export class SM2Error extends Error {
  /**
   * Create a new SM2 error instance
   * 
   * @param {string} message - Human-readable error description
   * @param {object} [options] - Additional error options
   * @param {string} [options.code] - Error code for programmatic handling
   * @param {Error} [options.cause] - Original error that caused this error
   * 
   * @example
   * // Basic error
   * throw new SM2Error('Operation failed');
   * 
   * // Error with code
   * throw new SM2Error('Invalid key', {
   *   code: 'ERR_KEY_INVALID'
   * });
   * 
   * // Error with cause
   * try {
   *   // ... operation
   * } catch (error) {
   *   throw new SM2Error('Key validation failed', {
   *     code: 'ERR_KEY_INVALID',
   *     cause: error
   *   });
   * }
   */
  constructor(message, { code, cause } = {}) {
    super(message, { cause });
    this.name = this.constructor.name;
    this.code = code;
  }
}

/**
 * Error class for key-related operations
 * 
 * Used when operations involving cryptographic keys fail, such as:
 * - Key generation
 * - Key validation
 * - Key format conversion
 * - Key pair operations
 * 
 * @extends SM2Error
 */
export class KeyError extends SM2Error {
  /**
   * Create Key Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_KEY', ...options });
  }
}

/**
 * Error class for signature operations
 * 
 * Used when digital signature operations fail, such as:
 * - Signature creation
 * - Signature format validation
 * - Signature encoding/decoding
 * 
 * @extends SM2Error
 */
export class SignatureError extends SM2Error {
  /**
   * Create Signature Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_SIGNATURE', ...options });
  }
}

/**
 * Error class for verification operations
 * 
 * Used when signature verification fails, including:
 * - Signature validation
 * - Verification method checks
 * - Proof purpose validation
 * - Chain of trust verification
 * 
 * @extends SM2Error
 */
export class VerificationError extends SM2Error {
  /**
   * Create Verification Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_VERIFICATION', ...options });
  }
}

/**
 * Error class for format-related operations
 * 
 * Used when data format operations fail, such as:
 * - Format validation
 * - Format conversion
 * - Encoding/decoding
 * - Schema validation
 * 
 * @extends SM2Error
 */
export class FormatError extends SM2Error {
  /**
   * Create Format Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_FORMAT', ...options });
  }
}

/**
 * Error class for argument validation
 * 
 * Used when function arguments are invalid, including:
 * - Missing required arguments
 * - Invalid argument types
 * - Invalid argument values
 * - Invalid argument combinations
 * 
 * @extends SM2Error
 */
export class ArgumentError extends SM2Error {
  /**
   * Create Argument Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_ARGUMENT', ...options });
  }
}

/**
 * Error class for general operations
 * 
 * Used for operational errors, such as:
 * - Unsupported operations
 * - Operation timeouts
 * - Resource constraints
 * - Internal errors
 * 
 * @extends SM2Error
 */
export class OperationError extends SM2Error {
  /**
   * Create Operation Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   */
  constructor(message, options) {
    super(message, { code: 'ERR_OPERATION', ...options });
  }
}

/**
 * Error class for key import operations
 * 
 * Used when key import operations fail, including:
 * - Format parsing errors
 * - Invalid key data
 * - Unsupported key types
 * - Import validation failures
 * 
 * @extends SM2Error
 */
export class ImportError extends SM2Error {
  /**
   * Create Key Import Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   * @param {object} [options.details] - Error details
   */
  constructor(message, options) {
    super(message, { code: 'ERR_IMPORT', ...options });
    this.details = options?.details;
  }
}

/**
 * Error class for key export operations
 * 
 * Used when key export operations fail, including:
 * - Format conversion errors
 * - Export restrictions
 * - Unsupported formats
 * - Export validation failures
 * 
 * @extends SM2Error
 */
export class ExportError extends SM2Error {
  /**
   * Create Key Export Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   * @param {object} [options.details] - Error details
   */
  constructor(message, options) {
    super(message, { code: 'ERR_EXPORT', ...options });
    this.details = options?.details;
  }
}

/**
 * Error class for encoding operations
 * 
 * Used when data encoding operations fail, such as:
 * - Base58 encoding
 * - DER encoding
 * - JWK encoding
 * - Format-specific encoding
 * 
 * @extends SM2Error
 */
export class EncodingError extends SM2Error {
  /**
   * Create Encoding Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   * @param {string} [options.encoding] - Encoding type
   */
  constructor(message, options) {
    super(message, { code: 'ERR_ENCODING', ...options });
    this.encoding = options?.encoding;
  }
}

/**
 * Error class for state-related errors
 * 
 * Used when operations fail due to invalid state, such as:
 * - Invalid operation sequence
 * - Missing prerequisites
 * - State validation failures
 * - Inconsistent state
 * 
 * @extends SM2Error
 */
export class StateError extends SM2Error {
  /**
   * Create State Error
   * @param {string} message - Error message
   * @param {object} options - Options
   * @param {string} [options.code] - Error code
   * @param {Error} [options.cause] - Error cause
   * @param {string} [options.state] - Current state
   */
  constructor(message, options) {
    super(message, { code: 'ERR_STATE', ...options });
    this.state = options?.state;
  }
}

/**
 * Comprehensive list of error codes
 * 
 * These codes are used for programmatic error handling and
 * consistent error reporting across the library.
 * 
 * Categories:
 * - Argument errors: Invalid or missing arguments
 * - Format errors: Data format and encoding issues
 * - Key errors: Key management and operations
 * - Signature errors: Signature creation and validation
 * - Verification errors: Signature verification process
 * - Import/Export errors: Key import/export operations
 * - Encoding errors: Data encoding/decoding operations
 * - Operation errors: General operational issues
 * - State errors: Invalid state conditions
 * 
 * @enum {string}
 */
export const ErrorCodes = {
  // Argument errors
  ERR_ARGUMENT_INVALID: 'ERR_ARGUMENT_INVALID', // Invalid argument
  ERR_ARGUMENT_MISSING: 'ERR_ARGUMENT_MISSING', // Missing argument

  // Format errors
  ERR_FORMAT_INVALID: 'ERR_FORMAT_INVALID',   // General format error
  ERR_FORMAT_INPUT: 'ERR_FORMAT_INPUT',       // Input validation error
  ERR_FORMAT_TYPE: 'ERR_FORMAT_TYPE',        // Type error
  ERR_FORMAT_LENGTH: 'ERR_FORMAT_LENGTH',    // Length error
  ERR_FORMAT_VALUE: 'ERR_FORMAT_VALUE',      // Value error
  ERR_FORMAT_OID: 'ERR_FORMAT_OID',          // Object identifier error
  ERR_FORMAT_ENCODE: 'ERR_FORMAT_ENCODE',    // Encoding error
  ERR_FORMAT_MULTIKEY: 'ERR_FORMAT_MULTIKEY', // Multikey format error
  ERR_FORMAT_MULTIBASE: 'ERR_FORMAT_MULTIBASE', // Multibase format error

  // Key errors
  ERR_KEY_INVALID: 'ERR_KEY_INVALID',        // Invalid key
  ERR_KEY_NOT_FOUND: 'ERR_KEY_NOT_FOUND',    // Key not found
  ERR_KEY_PAIR: 'ERR_KEY_PAIR',              // Key pair error
  ERR_KEY_FORMAT: 'ERR_KEY_FORMAT',          // Key format error
  ERR_KEY_GENERATION: 'ERR_KEY_GENERATION',  // Key generation error

  // Signature errors
  ERR_SIGNATURE_INVALID: 'ERR_SIGNATURE_INVALID', // Invalid signature

  // Verification errors
  ERR_VERIFICATION_FAILED: 'ERR_VERIFICATION_FAILED', // Verification failed

  // Import/Export errors
  ERR_IMPORT_FAILED: 'ERR_IMPORT_FAILED',     // Import failed
  ERR_EXPORT_FAILED: 'ERR_EXPORT_FAILED',     // Export failed

  // Operation errors
  ERR_OPERATION_INVALID: 'ERR_OPERATION_INVALID' // Invalid operation
};

/**
 * Error message templates for error codes
 * 
 * These templates support parameter substitution using {param}
 * syntax. Parameters are replaced when formatting error messages.
 * 
 * Template Rules:
 * - Use {param} for parameter placeholders
 * - Keep messages concise but informative
 * - Avoid exposing sensitive information
 * - Use consistent terminology
 * 
 * @enum {string}
 */
export const ErrorMessages = {
  [ErrorCodes.ERR_ARGUMENT_INVALID]: 'Invalid argument: {details}', // Invalid argument: {details}
  [ErrorCodes.ERR_ARGUMENT_MISSING]: 'Missing required argument: {argument}', // Missing argument: {argument}
  [ErrorCodes.ERR_FORMAT_INVALID]: 'Invalid format: {details}', // Invalid format: {details}
  [ErrorCodes.ERR_FORMAT_INPUT]: 'Invalid input: {details}', // Invalid input: {details}
  [ErrorCodes.ERR_FORMAT_TYPE]: 'Invalid type: {details}', // Invalid type: {details}
  [ErrorCodes.ERR_FORMAT_LENGTH]: 'Invalid length: {details}', // Invalid length: {details}
  [ErrorCodes.ERR_FORMAT_VALUE]: 'Invalid value: {details}', // Invalid value: {details}
  [ErrorCodes.ERR_FORMAT_OID]: 'Invalid object identifier: {details}', // Invalid object identifier: {details}
  [ErrorCodes.ERR_FORMAT_ENCODE]: 'Encoding error: {details}', // Encoding error: {details}
  [ErrorCodes.ERR_FORMAT_MULTIKEY]: 'Invalid multikey format: {details}', // Invalid multikey format: {details}
  [ErrorCodes.ERR_FORMAT_MULTIBASE]: 'Invalid multibase format: {details}', // Invalid multibase format: {details}
  [ErrorCodes.ERR_KEY_INVALID]: 'Invalid key: {details}', // Invalid key: {details}
  [ErrorCodes.ERR_KEY_NOT_FOUND]: 'Key not found: {id}', // Key not found: {id}
  [ErrorCodes.ERR_KEY_PAIR]: 'Invalid key pair: {details}', // Invalid key pair: {details}
  [ErrorCodes.ERR_KEY_FORMAT]: 'Invalid key format: {details}', // Invalid key format: {details}
  [ErrorCodes.ERR_KEY_GENERATION]: 'Key generation failed: {details}', // Key generation failed: {details}
  [ErrorCodes.ERR_SIGNATURE_INVALID]: 'Invalid signature: {details}', // Invalid signature: {details}
  [ErrorCodes.ERR_VERIFICATION_FAILED]: 'Verification failed: {details}', // Verification failed: {details}
  [ErrorCodes.ERR_IMPORT_FAILED]: 'Import failed: {details}', // Import failed: {details}
  [ErrorCodes.ERR_EXPORT_FAILED]: 'Export failed: {details}', // Export failed: {details}
  [ErrorCodes.ERR_OPERATION_INVALID]: 'Invalid operation: {details}' // Invalid operation: {details}
};

/**
 * Format an error message by replacing parameters in a template
 * 
 * This function replaces placeholders in the format {param} with
 * corresponding values from the params object. If a parameter is
 * not found in the params object, the placeholder is replaced
 * with an empty string.
 * 
 * Best Practices:
 * 1. Use descriptive parameter names
 * 2. Include all relevant context
 * 3. Keep messages concise but informative
 * 4. Avoid sensitive information
 * 
 * @param {string} template - Message template with {param} placeholders
 * @param {object} [params={}] - Parameters to substitute in template
 * @returns {string} Formatted error message
 * 
 * @example
 * // Basic usage
 * const msg = formatErrorMessage(
 *   'Invalid key type: {type}',
 *   { type: 'RSA' }
 * );
 * 
 * // Multiple parameters
 * const msg = formatErrorMessage(
 *   'Key {id} not found in format {format}',
 *   { id: 'abc123', format: 'JWK' }
 * );
 * 
 * // With optional parameters
 * const msg = formatErrorMessage(
 *   'Operation failed: {details}',
 *   { details: error.message }
 * );
 */
export function formatErrorMessage(template, params = {}) {
  if (typeof template !== 'string') {
    return 'Unknown error';
  }
  return template.replace(/\{(\w+)\}/g, (match, key) => {
    return params[key] !== undefined ? String(params[key]) : '';
  });
}

/**
 * Create an appropriate error instance based on error code
 * 
 * This factory function creates the most appropriate error instance
 * based on the error code, applying proper inheritance and adding
 * relevant context information.
 * 
 * Features:
 * - Automatic error class selection
 * - Message formatting with parameters
 * - Error cause tracking
 * - Additional context preservation
 * 
 * Best Practices:
 * 1. Use specific error codes
 * 2. Include relevant context
 * 3. Chain errors appropriately
 * 4. Handle errors at proper level
 * 
 * Error Selection Process:
 * 1. Determine error category from code
 * 2. Select appropriate error class
 * 3. Format error message
 * 4. Add context and cause
 * 
 * @param {string} code - Error code from ErrorCodes enum
 * @param {object} [params={}] - Additional error parameters
 * @param {Error} [cause] - Original error that caused this error
 * @returns {SM2Error} Appropriate error instance
 * 
 * @example
 * // Basic usage
 * throw createError(
 *   ErrorCodes.ERR_KEY_INVALID,
 *   { keyId: 'abc123' }
 * );
 * 
 * // With error chaining
 * try {
 *   await verifySignature(data);
 * } catch (error) {
 *   throw createError(
 *     ErrorCodes.ERR_VERIFICATION_FAILED,
 *     { signatureId: 'sig123' },
 *     error
 *   );
 * }
 * 
 * // With detailed context
 * throw createError(
 *   ErrorCodes.ERR_FORMAT_INVALID,
 *   {
 *     format: 'JWK',
 *     field: 'kty',
 *     expected: 'EC',
 *     received: 'RSA'
 *   }
 * );
 */
export function createError(code, params = {}, cause) {
  const message = formatErrorMessage(ErrorMessages[code] || code, params);
  const errorOptions = { code, ...params };
  if (cause) {
    errorOptions.cause = cause;
  }

  switch (code) {
    case ErrorCodes.ERR_ARGUMENT_INVALID:
    case ErrorCodes.ERR_ARGUMENT_MISSING:
      return new ArgumentError(message, errorOptions);

    case ErrorCodes.ERR_FORMAT_INVALID:
    case ErrorCodes.ERR_FORMAT_INPUT:
    case ErrorCodes.ERR_FORMAT_TYPE:
    case ErrorCodes.ERR_FORMAT_LENGTH:
    case ErrorCodes.ERR_FORMAT_VALUE:
    case ErrorCodes.ERR_FORMAT_OID:
    case ErrorCodes.ERR_FORMAT_ENCODE:
    case ErrorCodes.ERR_FORMAT_MULTIKEY:
    case ErrorCodes.ERR_FORMAT_MULTIBASE:
      return new FormatError(message, errorOptions);

    case ErrorCodes.ERR_KEY_INVALID:
    case ErrorCodes.ERR_KEY_NOT_FOUND:
    case ErrorCodes.ERR_KEY_PAIR:
    case ErrorCodes.ERR_KEY_FORMAT:
    case ErrorCodes.ERR_KEY_GENERATION:
      return new KeyError(message, errorOptions);

    case ErrorCodes.ERR_SIGNATURE_INVALID:
      return new SignatureError(message, errorOptions);

    case ErrorCodes.ERR_VERIFICATION_FAILED:
      return new VerificationError(message, errorOptions);

    case ErrorCodes.ERR_IMPORT_FAILED:
      return new ImportError(message, errorOptions);

    case ErrorCodes.ERR_EXPORT_FAILED:
      return new ExportError(message, errorOptions);

    case ErrorCodes.ERR_OPERATION_INVALID:
      return new OperationError(message, errorOptions);

    default:
      return new SM2Error(message, errorOptions);
  }
}
