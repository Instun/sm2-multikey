/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

import assert from 'node:assert';
import { describe, it, test } from 'node:test';
import {
  SM2Error,
  KeyError,
  SignatureError,
  VerificationError,
  FormatError,
  ArgumentError,
  OperationError,
  ImportError,
  ExportError,
  EncodingError,
  StateError,
  ErrorCodes,
  createError,
  formatErrorMessage
} from '../lib/core/errors.js';

describe('Errors', () => {
  describe('SM2Error', () => {
    it('should create error with message', () => {
      const error = new SM2Error('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'SM2Error');
      assert.strictEqual(error.code, undefined);
      assert.strictEqual(error.cause, undefined);
    });

    it('should create error with code', () => {
      const error = new SM2Error('test error', { code: 'TEST_ERROR' });
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.code, 'TEST_ERROR');
    });

    it('should create error with cause', () => {
      const cause = new Error('cause error');
      const error = new SM2Error('test error', { cause });
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.cause, cause);
    });
  });

  describe('KeyError', () => {
    it('should create error with default code', () => {
      const error = new KeyError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'KeyError');
      assert.strictEqual(error.code, 'ERR_KEY');
    });

    it('should create error with specific code', () => {
      const error = new KeyError('test error', { code: ErrorCodes.ERR_KEY_NOT_FOUND });
      assert.strictEqual(error.code, ErrorCodes.ERR_KEY_NOT_FOUND);
    });
  });

  describe('SignatureError', () => {
    it('should create error with default code', () => {
      const error = new SignatureError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'SignatureError');
      assert.strictEqual(error.code, 'ERR_SIGNATURE');
    });

    it('should create error with specific code', () => {
      const error = new SignatureError('test error', { code: ErrorCodes.ERR_SIGNATURE_INVALID });
      assert.strictEqual(error.code, ErrorCodes.ERR_SIGNATURE_INVALID);
    });
  });

  describe('VerificationError', () => {
    it('should create error with default code', () => {
      const error = new VerificationError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'VerificationError');
      assert.strictEqual(error.code, 'ERR_VERIFICATION');
    });

    it('should create error with specific code', () => {
      const error = new VerificationError('test error', { code: ErrorCodes.ERR_VERIFICATION_FAILED });
      assert.strictEqual(error.code, ErrorCodes.ERR_VERIFICATION_FAILED);
    });
  });

  describe('FormatError', () => {
    it('should create error with default code', () => {
      const error = new FormatError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'FormatError');
      assert.strictEqual(error.code, 'ERR_FORMAT');
    });

    it('should create error with specific code', () => {
      const error = new FormatError('test error', { code: ErrorCodes.ERR_FORMAT_INVALID });
      assert.strictEqual(error.code, ErrorCodes.ERR_FORMAT_INVALID);
    });
  });

  describe('ArgumentError', () => {
    it('should create error with default code', () => {
      const error = new ArgumentError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'ArgumentError');
      assert.strictEqual(error.code, 'ERR_ARGUMENT');
    });

    it('should create error with specific code', () => {
      const error = new ArgumentError('test error', { code: ErrorCodes.ERR_ARGUMENT_MISSING });
      assert.strictEqual(error.code, ErrorCodes.ERR_ARGUMENT_MISSING);
    });
  });

  describe('OperationError', () => {
    it('should create error with default code', () => {
      const error = new OperationError('test error');
      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.name, 'OperationError');
      assert.strictEqual(error.code, 'ERR_OPERATION');
    });

    it('should create error with specific code', () => {
      const error = new OperationError('test error', { code: ErrorCodes.ERR_OPERATION_FAILED });
      assert.strictEqual(error.code, ErrorCodes.ERR_OPERATION_FAILED);
    });
  });

  describe('Error Chain', () => {
    it('should create error chain', () => {
      const cause1 = new Error('cause 1');
      const cause2 = new KeyError('cause 2', { cause: cause1 });
      const cause3 = new SignatureError('cause 3', { cause: cause2 });
      const error = new VerificationError('test error', { cause: cause3 });

      assert.strictEqual(error.message, 'test error');
      assert.strictEqual(error.cause, cause3);
      assert.strictEqual(error.cause.cause, cause2);
      assert.strictEqual(error.cause.cause.cause, cause1);
    });
  });

  describe('Enhanced Error Handling', () => {
    test('Error message formatting', () => {
      const template = 'Invalid key type: {type}';
      const params = { type: 'RSA' };
      const message = formatErrorMessage(template, params);
      assert.equal(message, 'Invalid key type: RSA');
    });

    test('Create error with cause', () => {
      const cause = new Error('Original error');
      const error = createError(
        ErrorCodes.ERR_KEY_INVALID,
        { details: 'Invalid key type: RSA' },
        cause
      );
      assert.equal(error.message, 'Invalid key: Invalid key type: RSA');
      assert.equal(error.code, ErrorCodes.ERR_KEY_INVALID);
      assert.equal(error.cause, cause);
    });

    test('Import error with details', () => {
      const error = new ImportError('Failed to import key', {
        code: ErrorCodes.ERR_IMPORT_FAILED,
        details: { format: 'PEM' }
      });
      assert.equal(error.code, ErrorCodes.ERR_IMPORT_FAILED);
    });

    test('Export error with details', () => {
      const error = new ExportError('Failed to export key', {
        code: ErrorCodes.ERR_EXPORT_FAILED,
        details: { format: 'JWK' }
      });
      assert.equal(error.code, ErrorCodes.ERR_EXPORT_FAILED);
    });

    test('Encoding error with encoding type', () => {
      const error = new FormatError('Failed to encode data', {
        code: ErrorCodes.ERR_FORMAT_INVALID,
        details: { format: 'base64' }
      });
      assert.equal(error.code, ErrorCodes.ERR_FORMAT_INVALID);
    });

    test('State error with state info', () => {
      const error = new OperationError('Invalid operation state', {
        code: ErrorCodes.ERR_OPERATION_INVALID,
        details: { state: 'uninitialized' }
      });
      assert.equal(error.code, ErrorCodes.ERR_OPERATION_INVALID);
    });

    test('Error chain', () => {
      const cause = new Error('Network error');
      const error = createError(
        ErrorCodes.ERR_IMPORT_FAILED,
        { details: 'Failed to fetch key' },
        cause
      );
      assert.equal(error.message, 'Import failed: Failed to fetch key');
      assert.equal(error.cause, cause);
    });

    test('Error factory creates correct error types', () => {
      const keyError = createError(ErrorCodes.ERR_KEY_INVALID, { details: 'Invalid key type: RSA' });
      assert.ok(keyError instanceof KeyError);

      const sigError = createError(ErrorCodes.ERR_SIGNATURE_INVALID, { details: 'Bad length' });
      assert.ok(sigError instanceof SignatureError);

      const verifyError = createError(ErrorCodes.ERR_VERIFICATION_FAILED, { details: 'Bad signature' });
      assert.ok(verifyError instanceof VerificationError);

      const formatError = createError(ErrorCodes.ERR_FORMAT_INVALID, { details: 'Invalid format' });
      assert.ok(formatError instanceof FormatError);

      const argError = createError(ErrorCodes.ERR_ARGUMENT_INVALID, { details: 'Invalid argument type' });
      assert.ok(argError instanceof ArgumentError);

      const opError = createError(ErrorCodes.ERR_OPERATION_INVALID, { details: 'Invalid operation' });
      assert.ok(opError instanceof OperationError);

      const importError = createError(ErrorCodes.ERR_IMPORT_FAILED, { details: 'Import failed' });
      assert.ok(importError instanceof ImportError);

      const exportError = createError(ErrorCodes.ERR_EXPORT_FAILED, { details: 'Export failed' });
      assert.ok(exportError instanceof ExportError);
    });

    test('Error messages use templates', () => {
      const error = createError(ErrorCodes.ERR_KEY_INVALID, { details: 'Invalid key type: RSA' });
      assert.equal(error.message, 'Invalid key: Invalid key type: RSA');
    });
  });
});
