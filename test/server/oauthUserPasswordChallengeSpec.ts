/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai = require('chai')
import fs from 'graceful-fs'
const expect = chai.expect

/**
 * Tests verifying that the hardcoded password for oauthUserPasswordChallenge
 * has been removed from routes/login.ts and replaced with a reference to
 * process.env.OAUTH_USER_PASSWORD.
 *
 * CWE-259 Use of Hard-coded Password: The original code embedded the string
 * literal 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' directly in the source,
 * making it visible to anyone with repository access and impossible to rotate
 * without rebuilding the application.
 *
 * The fix replaces the string literal with process.env.OAUTH_USER_PASSWORD so
 * the secret is supplied at runtime via environment configuration and is never
 * committed to source control.
 */
describe('oauthUserPasswordChallenge hardcoded password fix', () => {
  let loginContent: string

  before(() => {
    loginContent = fs.readFileSync('routes/login.ts').toString()
  })

  describe('removal of hardcoded password', () => {
    it('should NOT contain the hardcoded base64 password literal', () => {
      // The old hardcoded credential must no longer appear in the source file
      expect(loginContent).not.to.include('bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
    })

    it('should NOT use a string literal comparison for the OAuth user password', () => {
      // Ensure no === comparison against a string literal containing the credential
      expect(loginContent).not.to.match(/===\s*'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='/)
      expect(loginContent).not.to.match(/'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='\s*===/)
    })
  })

  describe('environment variable usage', () => {
    it('should reference process.env.OAUTH_USER_PASSWORD instead of a literal', () => {
      expect(loginContent).to.include('process.env.OAUTH_USER_PASSWORD')
    })

    it('should compare the request password against process.env.OAUTH_USER_PASSWORD', () => {
      // The comparison must use the env variable as the right-hand side
      expect(loginContent).to.match(/req\.body\.password\s*===\s*process\.env\.OAUTH_USER_PASSWORD/)
    })

    it('should guard against empty password matching an unset env variable', () => {
      // An empty string should not satisfy the challenge when the env var is undefined
      // The fix must include a non-empty check on req.body.password
      expect(loginContent).to.match(/req\.body\.password\s*!==\s*''/)
    })
  })

  describe('challenge structure preservation', () => {
    it('should still check the oauthUserPasswordChallenge', () => {
      expect(loginContent).to.include('challenges.oauthUserPasswordChallenge')
    })

    it('should still verify the email belongs to bjoern.kimminich@gmail.com', () => {
      expect(loginContent).to.include('bjoern.kimminich@gmail.com')
    })

    it('should preserve the verifyPreLoginChallenges function', () => {
      expect(loginContent).to.include('function verifyPreLoginChallenges')
    })

    it('should preserve all other pre-login challenge checks', () => {
      expect(loginContent).to.include('challenges.weakPasswordChallenge')
      expect(loginContent).to.include('challenges.loginSupportChallenge')
      expect(loginContent).to.include('challenges.loginRapperChallenge')
      expect(loginContent).to.include('challenges.loginAmyChallenge')
      expect(loginContent).to.include('challenges.dlpPasswordSprayingChallenge')
    })
  })

  describe('file integrity', () => {
    it('should be a valid TypeScript/JavaScript file with balanced braces', () => {
      const openBraces = (loginContent.match(/\{/g) ?? []).length
      const closeBraces = (loginContent.match(/\}/g) ?? []).length
      expect(openBraces).to.equal(closeBraces)
    })

    it('should preserve the module.exports login function structure', () => {
      expect(loginContent).to.match(/module\.exports\s*=\s*function login/)
    })

    it('should preserve the afterLogin helper function', () => {
      expect(loginContent).to.include('function afterLogin')
    })

    it('should preserve 2FA (TOTP) handling logic', () => {
      expect(loginContent).to.include('totp_token_required')
    })
  })
})

/**
 * Unit-style tests for the challenge verification logic: simulate the
 * lambda passed to challengeUtils.solveIf under different conditions.
 */
describe('oauthUserPasswordChallenge lambda logic (unit)', () => {
  const OAUTH_EMAIL = 'bjoern.kimminich@gmail.com'
  const CORRECT_PASSWORD = 'test-runtime-secret'

  /**
   * Reconstruct the lambda from the fixed source so we can exercise it
   * independently of the full Express/Sequelize stack.
   *
   * The lambda checks:
   *   req.body.email === OAUTH_EMAIL &&
   *   req.body.password !== '' &&
   *   req.body.password === process.env.OAUTH_USER_PASSWORD
   */
  function buildLambda (email: string, password: string): boolean {
    const envPassword = process.env.OAUTH_USER_PASSWORD ?? ''
    return (
      email === OAUTH_EMAIL &&
      password !== '' &&
      password === envPassword
    )
  }

  describe('when OAUTH_USER_PASSWORD env var is set', () => {
    before(() => {
      process.env.OAUTH_USER_PASSWORD = CORRECT_PASSWORD
    })

    after(() => {
      delete process.env.OAUTH_USER_PASSWORD
    })

    it('should return true for correct email and correct password', () => {
      expect(buildLambda(OAUTH_EMAIL, CORRECT_PASSWORD)).to.equal(true)
    })

    it('should return false for wrong email with correct password', () => {
      expect(buildLambda('other@example.com', CORRECT_PASSWORD)).to.equal(false)
    })

    it('should return false for correct email with wrong password', () => {
      expect(buildLambda(OAUTH_EMAIL, 'wrong-password')).to.equal(false)
    })

    it('should return false for correct email with empty password', () => {
      expect(buildLambda(OAUTH_EMAIL, '')).to.equal(false)
    })

    it('should return false for both wrong email and wrong password', () => {
      expect(buildLambda('attacker@evil.com', 'wrong')).to.equal(false)
    })
  })

  describe('when OAUTH_USER_PASSWORD env var is NOT set', () => {
    before(() => {
      delete process.env.OAUTH_USER_PASSWORD
    })

    it('should return false regardless of password provided', () => {
      // Without the env var, no password should satisfy the check
      expect(buildLambda(OAUTH_EMAIL, 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')).to.equal(false)
    })

    it('should return false for empty password', () => {
      expect(buildLambda(OAUTH_EMAIL, '')).to.equal(false)
    })

    it('should return false for any arbitrary password', () => {
      expect(buildLambda(OAUTH_EMAIL, 'any-password-at-all')).to.equal(false)
    })
  })
})
