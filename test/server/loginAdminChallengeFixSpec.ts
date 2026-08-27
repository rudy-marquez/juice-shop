/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'
const expect = chai.expect

/**
 * Tests verifying that loginAdminChallenge_1.ts has been remediated to use
 * parameterized queries (Sequelize bind parameters) instead of unsafe string
 * interpolation with user-supplied input.
 *
 * CWE-89 SQL Injection: The original code embedded req.body.email and
 * security.hash(req.body.password) directly into a SQL template literal,
 * allowing attackers to inject arbitrary SQL syntax through either field.
 *
 * The fix replaces the interpolated template literal with Sequelize's $1/$2
 * positional bind parameters, equivalent to a prepared statement.
 */
describe('loginAdminChallenge_1 SQL Injection fix', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync('data/static/codefixes/loginAdminChallenge_1.ts').toString()
  })

  describe('parameterized query usage', () => {
    it('should use Sequelize bind parameters ($1, $2) instead of template literal interpolation', () => {
      expect(fixContent).to.match(/\$1/)
      expect(fixContent).to.match(/\$2/)
    })

    it('should include a bind array passed to sequelize.query', () => {
      // The fix must supply a bind array: { bind: [...], ... }
      expect(fixContent).to.match(/bind\s*:\s*\[/)
    })

    it('should NOT embed req.body.email directly inside the SQL template string', () => {
      // Detect direct interpolation of req.body.email inside a template literal
      expect(fixContent).not.to.match(/`[^`]*\$\{[^}]*req\.body\.email[^}]*\}[^`]*`/)
    })

    it('should NOT embed req.body.password directly inside the SQL template string', () => {
      // Detect direct interpolation of req.body.password (or security.hash(req.body.password)) inside a template literal
      expect(fixContent).not.to.match(/`[^`]*\$\{[^}]*req\.body\.password[^}]*\}[^`]*`/)
    })

    it('should NOT use a blocklist regex as the primary SQL injection defense', () => {
      // The insecure original relied on a regex blocklist check instead of parameterization;
      // the secure fix must not rely on regex matching as the primary guard.
      expect(fixContent).not.to.match(/\.match\s*\(\s*\/\.\*\[/)
    })

    it('should still pass the hashed password to the bind array, not the raw password', () => {
      // Passwords must be hashed before comparison; ensure security.hash is used in the bind array
      expect(fixContent).to.match(/security\.hash\s*\(\s*req\.body\.password/)
    })
  })

  describe('query structure', () => {
    it('should contain a SELECT query for Users table', () => {
      expect(fixContent).to.match(/SELECT \* FROM Users/)
    })

    it('should query both email and password columns with bind placeholders', () => {
      expect(fixContent).to.match(/email\s*=\s*\$1/)
      expect(fixContent).to.match(/password\s*=\s*\$2/)
    })

    it('should still filter out soft-deleted users with deletedAt IS NULL', () => {
      expect(fixContent).to.match(/deletedAt IS NULL/)
    })
  })

  describe('fix file integrity', () => {
    it('should be a valid TypeScript/JavaScript file with balanced braces', () => {
      const openBraces = (fixContent.match(/\{/g) ?? []).length
      const closeBraces = (fixContent.match(/\}/g) ?? []).length
      expect(openBraces).to.equal(closeBraces)
    })

    it('should preserve the afterLogin helper function', () => {
      expect(fixContent).to.include('function afterLogin')
    })

    it('should preserve 2FA (TOTP) handling logic', () => {
      expect(fixContent).to.include('totp_token_required')
    })

    it('should preserve the module.exports login function structure', () => {
      expect(fixContent).to.match(/module\.exports\s*=\s*function login/)
    })
  })
})
