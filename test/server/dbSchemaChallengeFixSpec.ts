/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'

const expect = chai.expect

describe('dbSchemaChallenge_1 SQL Injection fix', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync('./data/static/codefixes/dbSchemaChallenge_1.ts').toString()
  })

  it('should not use string concatenation to build the SQL query', () => {
    // The vulnerable pattern embeds criteria directly into the query string via concatenation
    expect(fixContent).to.not.include("'%\"+criteria+\"%'")
    expect(fixContent).to.not.include("'%\" + criteria + \"%'")
    expect(fixContent).to.not.include("criteria+\"%'")
  })

  it('should use a parameterized query with replacements to prevent SQL injection', () => {
    // The safe pattern uses Sequelize replacements (equivalent to prepared statements)
    expect(fixContent).to.include('replacements')
    expect(fixContent).to.include('criteria')
  })

  it('should use named replacement placeholder for criteria in the query template', () => {
    // Named placeholder :criteria in template literal ensures parameter binding, not concatenation
    expect(fixContent).to.include(':criteria')
  })

  it('should pass the criteria value inside the replacements object', () => {
    // The replacements object must reference the criteria variable
    expect(fixContent).to.match(/replacements\s*:\s*\{[^}]*criteria[^}]*\}/)
  })

  it('should still contain the correct SQL WHERE clause structure', () => {
    // Functional correctness: the query logic must be preserved
    expect(fixContent).to.include('SELECT * FROM Products')
    expect(fixContent).to.include('name LIKE')
    expect(fixContent).to.include('description LIKE')
    expect(fixContent).to.include('deletedAt IS NULL')
    expect(fixContent).to.include('ORDER BY name')
  })

  it('should truncate criteria to 200 characters as an additional safeguard', () => {
    // Defence-in-depth: input length restriction is preserved
    expect(fixContent).to.include('200')
    expect(fixContent).to.include('substring')
  })

  it('should handle undefined query parameter gracefully', () => {
    // Edge-case handling for missing q parameter must be preserved
    expect(fixContent).to.include("'undefined'")
    expect(fixContent).to.include("req.query.q")
  })
})
