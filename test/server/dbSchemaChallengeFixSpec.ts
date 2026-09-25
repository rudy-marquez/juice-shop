/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'
const expect = chai.expect

/**
 * Tests verifying that dbSchemaChallenge_3.ts has been remediated to use
 * Sequelize named replacements (parameterized queries) instead of unsafe
 * string interpolation with user-supplied input.
 *
 * CWE-89 SQL Injection: The original code embedded `criteria` (derived from
 * req.query.q) directly into a SQL template literal using `${criteria}`,
 * allowing attackers to inject arbitrary SQL through the search query parameter.
 *
 * The fix replaces the interpolated template literal with Sequelize's named
 * replacement `:criteria`, passing the search value via the `replacements`
 * option — equivalent to a prepared statement.
 */
describe('dbSchemaChallenge_3 SQL Injection fix', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync('data/static/codefixes/dbSchemaChallenge_3.ts').toString()
  })

  describe('parameterized query usage', () => {
    it('should use a named Sequelize replacement placeholder (:criteria) in the SQL query', () => {
      expect(fixContent).to.match(/:criteria/)
    })

    it('should pass replacements option to sequelize.query', () => {
      // The fix must supply a replacements object: { replacements: { criteria: ... } }
      expect(fixContent).to.match(/replacements\s*:\s*\{/)
    })

    it('should NOT embed criteria directly inside the SQL template string via interpolation', () => {
      // Detect direct interpolation of `criteria` inside a template literal (the vulnerable pattern)
      expect(fixContent).not.to.match(/`[^`]*\$\{[^}]*criteria[^}]*\}[^`]*`/)
    })

    it('should NOT rely on a blocklist regex as the primary SQL injection defense', () => {
      // The insecure _1 variant relied on a regex blocklist (/"|\'|;|and|or|;|#/i);
      // the secure fix must not use regex matching as the primary guard.
      expect(fixContent).not.to.match(/injectionChars/)
    })

    it('should NOT use the insecure injection-char blocklist pattern', () => {
      expect(fixContent).not.to.match(/\/["';]|and|or/)
    })

    it('should embed wildcard characters in the replacement value, not in the SQL string', () => {
      // The LIKE wildcards should appear in the replacements value (e.g. `%${criteria}%`)
      // rather than as literals inside the SQL string adjacent to the placeholder.
      expect(fixContent).to.match(/criteria\s*:\s*[`'"]?%/)
    })
  })

  describe('query structure', () => {
    it('should contain a SELECT query for Products table', () => {
      expect(fixContent).to.match(/SELECT \* FROM Products/)
    })

    it('should filter by both name and description columns using the safe placeholder', () => {
      expect(fixContent).to.match(/name LIKE :criteria/)
      expect(fixContent).to.match(/description LIKE :criteria/)
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

    it('should preserve the length-limiting truncation of the search criteria', () => {
      // Input is capped at 200 characters to limit query size
      expect(fixContent).to.match(/criteria\.length\s*<=\s*200/)
    })

    it('should preserve the response JSON helper call', () => {
      expect(fixContent).to.match(/utils\.queryResultToJson/)
    })

    it('should preserve the i18n translation calls for product name and description', () => {
      expect(fixContent).to.match(/req\.__\s*\(products\[i\]\.name\)/)
      expect(fixContent).to.match(/req\.__\s*\(products\[i\]\.description\)/)
    })

    it('should preserve error handling via next()', () => {
      expect(fixContent).to.match(/next\s*\(/)
    })
  })
})
