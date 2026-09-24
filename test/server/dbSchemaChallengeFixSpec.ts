/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'
const expect = chai.expect

/**
 * Tests verifying that dbSchemaChallenge_1.ts has been remediated to use
 * Sequelize named replacements (parameterized queries) instead of unsafe string
 * concatenation with user-supplied input.
 *
 * CWE-89 SQL Injection: The original code embedded the `criteria` variable
 * (derived from req.query.q) directly into a SQL string via concatenation
 * ("...%"+criteria+"%..."), allowing attackers to inject arbitrary SQL syntax.
 *
 * The fix replaces concatenation with Sequelize's :criteria named replacement,
 * which is equivalent to a prepared statement and prevents SQL injection.
 */
describe('dbSchemaChallenge_1 SQL Injection fix', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync('data/static/codefixes/dbSchemaChallenge_1.ts').toString()
  })

  describe('parameterized query usage', () => {
    it('should use Sequelize named replacements (:criteria) instead of string concatenation', () => {
      // The fix must use named placeholder :criteria in the SQL query
      expect(fixContent).to.match(/:criteria/)
    })

    it('should include a replacements object passed to sequelize.query', () => {
      // The fix must supply replacements: { criteria: ... } to sequelize.query
      expect(fixContent).to.match(/replacements\s*:\s*\{/)
    })

    it('should pass the LIKE wildcard pattern as part of the replacement value, not embedded in SQL', () => {
      // The % wildcards should be part of the replacement value (e.g., `%${criteria}%`),
      // not concatenated directly into the SQL string
      expect(fixContent).to.match(/criteria\s*:\s*`%\$\{criteria\}%`/)
    })

    it('should NOT use direct string concatenation of criteria into the SQL query', () => {
      // The original vulnerable pattern used "...%" + criteria + "%..."
      expect(fixContent).not.to.match(/['"`][^'"`]*%['"`]\s*\+\s*criteria/)
    })

    it('should NOT embed criteria directly via template literal interpolation in the SQL string', () => {
      // Template literal interpolation of criteria inside the SQL string is also unsafe
      expect(fixContent).not.to.match(/LIKE\s+['"`]%\$\{criteria\}%['"`]/)
    })

    it('should NOT use a blocklist regex as the primary SQL injection defense', () => {
      // Regex-based blocklists are not a recognized sanitizer and can be bypassed
      expect(fixContent).not.to.match(/injectionChars\s*=\s*\//)
    })
  })

  describe('query structure', () => {
    it('should contain a SELECT query for Products table', () => {
      expect(fixContent).to.match(/SELECT \* FROM Products/)
    })

    it('should search in both name and description columns', () => {
      expect(fixContent).to.match(/name LIKE/)
      expect(fixContent).to.match(/description LIKE/)
    })

    it('should still filter out soft-deleted products with deletedAt IS NULL', () => {
      expect(fixContent).to.match(/deletedAt IS NULL/)
    })

    it('should still order results by name', () => {
      expect(fixContent).to.match(/ORDER BY name/)
    })
  })

  describe('fix file integrity', () => {
    it('should be a valid TypeScript/JavaScript file with balanced braces', () => {
      const openBraces = (fixContent.match(/\{/g) ?? []).length
      const closeBraces = (fixContent.match(/\}/g) ?? []).length
      expect(openBraces).to.equal(closeBraces)
    })

    it('should preserve the module.exports searchProducts function structure', () => {
      expect(fixContent).to.match(/module\.exports\s*=\s*function searchProducts/)
    })

    it('should preserve the criteria length truncation guard', () => {
      // Input length limiting (200 chars) should still be present
      expect(fixContent).to.match(/criteria\.length\s*<=\s*200/)
    })

    it('should preserve the undefined check for query parameter q', () => {
      // The guard against the string "undefined" from req.query.q should remain
      expect(fixContent).to.match(/req\.query\.q\s*===\s*'undefined'/)
    })

    it('should preserve the JSON response with utils.queryResultToJson', () => {
      expect(fixContent).to.match(/utils\.queryResultToJson\(products\)/)
    })

    it('should preserve the error handling via next(error.parent)', () => {
      expect(fixContent).to.match(/next\s*\(\s*error\.parent\s*\)/)
    })
  })

  describe('security properties', () => {
    it('should not introduce new string interpolation of user input in SQL context', () => {
      // Verify that the only interpolation of criteria is inside the replacements value,
      // not directly in the SQL query string
      const sqlQueryMatch = fixContent.match(/sequelize\.query\s*\(\s*(['"`])([\s\S]*?)\1/)
      if (sqlQueryMatch) {
        const sqlString = sqlQueryMatch[2]
        // The SQL string itself must not contain ${criteria}
        expect(sqlString).not.to.include('${criteria}')
      }
    })

    it('should use a single :criteria placeholder (reused for both name and description)', () => {
      // Efficient and safe: the same named replacement used twice in the query
      const matches = fixContent.match(/:criteria/g)
      expect(matches).to.have.length.at.least(2)
    })
  })
})
