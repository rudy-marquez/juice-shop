/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'

const expect = chai.expect

const fixFile = 'data/static/codefixes/unionSqlInjectionChallenge_3.ts'

describe('unionSqlInjectionChallenge fix option 3', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync(fixFile, 'utf8')
  })

  it('should exist as a code fix option file', () => {
    expect(fs.existsSync(fixFile)).to.equal(true)
  })

  it('should use a parameterized query (positional ? replacements)', () => {
    // The safe fix must contain a '?' placeholder for Sequelize's positional replacements
    expect(fixContent).to.include('?')
    expect(fixContent).to.include('replacements')
  })

  it('should NOT interpolate criteria directly into the SQL template string', () => {
    // Direct interpolation of criteria into the query is the vulnerability.
    // A SQL template that embeds ${criteria} inside the query string is unsafe.
    expect(fixContent).to.not.match(/LIKE\s+['"`]%\$\{criteria\}%['"`]/)
  })

  it('should NOT use a blocklist / startsWith check as primary defense', () => {
    // Using startsWith() to filter search terms does not prevent UNION-based SQL injection
    // (e.g. "apple')) UNION SELECT ...--") and therefore must not be the sole protection.
    expect(fixContent).to.not.include('.startsWith(')
  })

  it('should NOT use regex replace as the only sanitization mechanism', () => {
    // Regex-based blocklists are insufficient to prevent all SQL injection payloads.
    expect(fixContent).to.not.match(/\.replace\(\/.*?\/i?,\s*["']["']?\)/)
  })

  it('should query the Products table with LIKE wildcards supplied as replacement values', () => {
    // The % wildcards must be bound as parameter values, not embedded directly in the SQL string.
    // Valid patterns: replacements: [`%${criteria}%`, `%${criteria}%`]
    expect(fixContent).to.match(/replacements\s*:\s*\[/)
    expect(fixContent).to.match(/%\$\{criteria\}%/)
  })

  it('should preserve the ORDER BY name clause for correct product listing', () => {
    expect(fixContent).to.include('ORDER BY name')
  })

  it('should preserve deletedAt IS NULL filter to exclude soft-deleted products', () => {
    expect(fixContent).to.include('deletedAt IS NULL')
  })
})
