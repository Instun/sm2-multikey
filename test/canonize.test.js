/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cryptosuite } from './config.js';

describe('URDNA2015 Canonization', () => {
  it('should canonize simple document', async () => {
    const input = {
      '@context': {
        '@version': 1.1,
        'name': 'https://schema.org/name',
        'age': 'https://schema.org/age'
      },
      'name': 'Alice',
      'age': 30
    };

    const output = await cryptosuite.canonize(input);
    assert.ok(output.includes('schema.org/name'));
    assert.ok(output.includes('"Alice"'));
    assert.ok(output.includes('schema.org/age'));
    assert.ok(output.includes('"30"'));
  });

  it('should produce identical output for equivalent documents', async () => {
    const doc1 = {
      '@context': {
        '@version': 1.1,
        'a': 'https://example.org/a',
        'b': 'https://example.org/b'
      },
      'b': 2,
      'a': 1
    };

    const doc2 = {
      'a': 1,
      '@context': {
        '@version': 1.1,
        'a': 'https://example.org/a',
        'b': 'https://example.org/b'
      },
      'b': 2
    };

    const output1 = await cryptosuite.canonize(doc1);
    const output2 = await cryptosuite.canonize(doc2);
    assert.strictEqual(output1, output2);
  });

  it('should handle nested objects', async () => {
    const input = {
      '@context': {
        '@version': 1.1,
        'person': 'https://schema.org/Person',
        'name': 'https://schema.org/name',
        'address': 'https://schema.org/address',
        'city': 'https://schema.org/addressLocality',
        'country': 'https://schema.org/addressCountry'
      },
      'person': {
        'name': 'Bob',
        'address': {
          'city': 'London',
          'country': 'UK'
        }
      }
    };

    const output = await cryptosuite.canonize(input);
    assert.ok(output.includes('schema.org/name'));
    assert.ok(output.includes('"Bob"'));
    assert.ok(output.includes('schema.org/addressLocality'));
    assert.ok(output.includes('"London"'));
    assert.ok(output.includes('schema.org/addressCountry'));
    assert.ok(output.includes('"UK"'));
  });

  it('should handle arrays', async () => {
    const input = {
      '@context': {
        '@version': 1.1,
        'numbers': 'https://example.org/numbers',
        'strings': 'https://example.org/strings'
      },
      'numbers': [3, 1, 4, 1, 5],
      'strings': ['c', 'a', 'b']
    };

    const output = await cryptosuite.canonize(input);
    assert.ok(output.includes('example.org/numbers'));
    assert.ok(output.includes('"1"'));
    assert.ok(output.includes('"3"'));
    assert.ok(output.includes('"4"'));
    assert.ok(output.includes('"5"'));
    assert.ok(output.includes('example.org/strings'));
    assert.ok(output.includes('"a"'));
    assert.ok(output.includes('"b"'));
    assert.ok(output.includes('"c"'));
  });

  it('should handle null values', async () => {
    const input = {
      '@context': {
        '@version': 1.1,
        'nullValue': 'https://example.org/nullValue',
        'definedValue': 'https://example.org/definedValue'
      },
      'nullValue': null,
      'definedValue': 'test'
    };

    const output = await cryptosuite.canonize(input);
    assert.ok(!output.includes('nullValue'));
    assert.ok(output.includes('example.org/definedValue'));
    assert.ok(output.includes('"test"'));
  });

});
