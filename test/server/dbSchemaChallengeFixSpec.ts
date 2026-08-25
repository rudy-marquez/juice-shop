/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'
const expect = chai.expect

/**
 * Tests to verify that dbSchemaChallenge_1.ts has been fixed to use
 * parameterized queries (Sequelize replacements) instead of raw SQL
 * string concatenation, eliminating the SQL Injection vulnerability (CWE-89).
 */
describe('dbSchemaChallenge fix - SQL Injection remediation', () => {
  let fixSource: string

  before(() => {
    fixSource = fs.readFileSync('./data/static/codefixes/dbSchemaChallenge_1.ts', 'utf8')
  })

  it('should not use string concatenation to build the SQL query', () => {
    // SQL injection via concatenation: "SELECT ... '"+criteria+"'..."
    const concatenationPattern = /['"`]\s*\+\s*criteria\s*\+\s*['"`]/
    expect(
      concatenationPattern.test(fixSource),
      'dbSchemaChallenge_1.ts must not concatenate "criteria" directly into the SQL string'
    ).to.equal(false)
  })

  it('should not use template literal interpolation to embed criteria directly in the SQL string', () => {
    // Template literal injection: `... ${criteria} ...`
    const templateInjectionPattern = /\$\{criteria\}/
    expect(
      templateInjectionPattern.test(fixSource),
      'dbSchemaChallenge_1.ts must not interpolate "criteria" directly into a template-literal SQL string'
    ).to.equal(false)
  })

  it('should use Sequelize named replacements (:criteria) as a parameterized placeholder', () => {
    // Parameterized placeholder in the SQL string
    const namedPlaceholderPattern = /:criteria/
    expect(
      namedPlaceholderPattern.test(fixSource),
      'dbSchemaChallenge_1.ts must use the :criteria named replacement placeholder in the SQL query'
    ).to.equal(true)
  })

  it('should pass replacements option to sequelize.query to bind the parameter safely', () => {
    // Sequelize replacements object: { replacements: { criteria: ... } }
    const replacementsOptionPattern = /replacements\s*:\s*\{[^}]*criteria/
    expect(
      replacementsOptionPattern.test(fixSource),
      'dbSchemaChallenge_1.ts must supply a replacements object with the criteria key to sequelize.query'
    ).to.equal(true)
  })

  it('should still call models.sequelize.query for product search functionality', () => {
    expect(
      fixSource.includes('models.sequelize.query'),
      'dbSchemaChallenge_1.ts must still invoke models.sequelize.query'
    ).to.equal(true)
  })

  it('should still include the expected SQL WHERE clause structure', () => {
    // The SELECT statement must still filter on name and description columns
    expect(
      fixSource.includes('name LIKE') && fixSource.includes('description LIKE'),
      'dbSchemaChallenge_1.ts must still filter on name and description columns'
    ).to.equal(true)
  })

  it('should still filter out soft-deleted products via deletedAt IS NULL', () => {
    expect(
      fixSource.includes('deletedAt IS NULL'),
      'dbSchemaChallenge_1.ts must still include the deletedAt IS NULL condition'
    ).to.equal(true)
  })
})
