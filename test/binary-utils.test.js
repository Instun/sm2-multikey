import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  isValidBinaryData,
  toBuffer,
  toUint8Array,
  matchBinaryType
} from '../lib/utils/binary.js';
import { ArgumentError } from '../lib/core/errors.js';

describe('Binary Utils', () => {
  const testData = [1, 2, 3, 4];
  const buffer = Buffer.from(testData);
  const uint8Array = new Uint8Array(testData);

  describe('isValidBinaryData', () => {
    it('should return true for Buffer', () => {
      assert.equal(isValidBinaryData(buffer), true);
    });

    it('should return true for Uint8Array', () => {
      assert.equal(isValidBinaryData(uint8Array), true);
    });

    it('should return false for other types', () => {
      assert.equal(isValidBinaryData(null), false);
      assert.equal(isValidBinaryData(undefined), false);
      assert.equal(isValidBinaryData(123), false);
      assert.equal(isValidBinaryData('string'), false);
      assert.equal(isValidBinaryData([]), false);
      assert.equal(isValidBinaryData({}), false);
    });
  });

  describe('toBuffer', () => {
    it('should return same Buffer if input is Buffer', () => {
      const result = toBuffer(buffer);
      assert.equal(result, buffer);
      assert.ok(Buffer.isBuffer(result));
    });

    it('should convert Uint8Array to Buffer', () => {
      const result = toBuffer(uint8Array);
      assert.ok(Buffer.isBuffer(result));
      assert.deepEqual([...result], testData);
    });

    it('should throw for invalid input', () => {
      assert.throws(() => toBuffer(null), ArgumentError);
      assert.throws(() => toBuffer(undefined), ArgumentError);
      assert.throws(() => toBuffer(123), ArgumentError);
      assert.throws(() => toBuffer('string'), ArgumentError);
      assert.throws(() => toBuffer([]), ArgumentError);
      assert.throws(() => toBuffer({}), ArgumentError);
    });
  });

  describe('toUint8Array', () => {
    it('should return same Uint8Array if input is Uint8Array (non-Buffer)', () => {
      const plainUint8Array = new Uint8Array(testData);
      const result = toUint8Array(plainUint8Array);
      assert.equal(result, plainUint8Array);
      assert.ok(result instanceof Uint8Array);
      assert.ok(!Buffer.isBuffer(result));
    });

    it('should convert Buffer to Uint8Array', () => {
      const result = toUint8Array(buffer);
      assert.ok(result instanceof Uint8Array);
      assert.ok(!Buffer.isBuffer(result));
      assert.deepEqual([...result], testData);
    });

    it('should throw for invalid input', () => {
      assert.throws(() => toUint8Array(null), ArgumentError);
      assert.throws(() => toUint8Array(undefined), ArgumentError);
      assert.throws(() => toUint8Array(123), ArgumentError);
      assert.throws(() => toUint8Array('string'), ArgumentError);
      assert.throws(() => toUint8Array([]), ArgumentError);
      assert.throws(() => toUint8Array({}), ArgumentError);
    });
  });

  describe('matchBinaryType', () => {
    it('should return Buffer when template is Buffer', () => {
      const result = matchBinaryType(buffer, uint8Array);
      assert.ok(Buffer.isBuffer(result));
      assert.deepEqual([...result], testData);
    });

    it('should return Uint8Array when template is Uint8Array', () => {
      const result = matchBinaryType(uint8Array, buffer);
      assert.ok(result instanceof Uint8Array);
      assert.ok(!Buffer.isBuffer(result));
      assert.deepEqual([...result], testData);
    });

    it('should throw for invalid template', () => {
      assert.throws(() => matchBinaryType(null, buffer), ArgumentError);
      assert.throws(() => matchBinaryType(undefined, buffer), ArgumentError);
      assert.throws(() => matchBinaryType(123, buffer), ArgumentError);
      assert.throws(() => matchBinaryType('string', buffer), ArgumentError);
      assert.throws(() => matchBinaryType([], buffer), ArgumentError);
      assert.throws(() => matchBinaryType({}, buffer), ArgumentError);
    });

    it('should throw for invalid data', () => {
      assert.throws(() => matchBinaryType(buffer, null), ArgumentError);
      assert.throws(() => matchBinaryType(buffer, undefined), ArgumentError);
      assert.throws(() => matchBinaryType(buffer, 123), ArgumentError);
      assert.throws(() => matchBinaryType(buffer, 'string'), ArgumentError);
      assert.throws(() => matchBinaryType(buffer, []), ArgumentError);
      assert.throws(() => matchBinaryType(buffer, {}), ArgumentError);
    });
  });
});
