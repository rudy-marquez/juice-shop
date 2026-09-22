/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'graceful-fs'
import chai = require('chai')
const expect = chai.expect

const FIXES_DIR = 'data/static/codefixes'
const CHALLENGE_KEY = 'unionSqlInjectionChallenge'

describe('unionSqlInjectionChallenge fix (file 1)', () => {
  let fixContent: string

  before(() => {
    fixContent = fs.readFileSync(`${FIXES_DIR}/${CHALLENGE_KEY}_1.ts`).toString()
  })

  describe('parameterized query usage', () => {
    it('should use Sequelize replacements object for parameterized query binding', () => {
      // The fix must pass a replacements object to prevent SQL injection
      expect(fixContent).to.include('replacements')
    })

    it('should use named placeholder :criteria in the SQL query string', () => {
      // Sequelize named replacements use :name placeholders instead of interpolated variables
      expect(fixContent).to.include(':criteria')
    })

    it('should NOT use template literal interpolation of criteria in the SQL query', () => {
      // String interpolation of user input into SQL is the vulnerability — must be absent
      expect(fixContent).to.not.include('`%${criteria}%`')
      expect(fixContent).to.not.include("'%" + "' + criteria + '%" + "'")
    })

    it('should NOT use string concatenation to build the SQL query with criteria', () => {
      // Any form of concatenating criteria directly into the query string is unsafe
      expect(fixContent).to.not.match(/['"`].*\$\{criteria\}.*['"`]/)
    })
  })

  describe('blocklist removal', () => {
    it('should NOT rely on a regex-based blocklist to sanitize user input', () => {
      // Regex blocklists are easily bypassed and are not an acceptable SQL injection mitigation
      expect(fixContent).to.not.include('criteria.replace(')
    })

    it('should NOT contain the original insecure blocklist pattern for SQL keywords', () => {
      // The vulnerable version tried to strip quotes, semicolons and SQL keywords via regex
      expect(fixContent).to.not.match(/replace\(.*["'|;].*and.*or/i)
    })
  })

  describe('query structure', () => {
    it('should still query the Products table', () => {
      expect(fixContent).to.include('FROM Products')
    })

    it('should still filter by name and description using LIKE', () => {
      expect(fixContent).to.include('name LIKE')
      expect(fixContent).to.include('description LIKE')
    })

    it('should still exclude logically deleted products via deletedAt IS NULL', () => {
      expect(fixContent).to.include('deletedAt IS NULL')
    })

    it('should still order results by name', () => {
      expect(fixContent).to.include('ORDER BY name')
    })
  })

  describe('input length guard', () => {
    it('should still truncate criteria to 200 characters to limit payload size', () => {
      // Length limiting is a defence-in-depth measure that should be retained
      expect(fixContent).to.include('200')
      expect(fixContent).to.include('substring(0, 200)')
    })
  })
})

describe('unionSqlInjectionChallenge fix set', () => {
  it('should have exactly 3 fix options for the challenge', () => {
    const files = fs.readdirSync(FIXES_DIR)
    const fixFiles = files.filter((f: string) => f.startsWith(`${CHALLENGE_KEY}_`))
    expect(fixFiles.length).to.equal(3)
  })

  it('should designate fix #2 as the correct fix (parameterized query)', () => {
    const files = fs.readdirSync(FIXES_DIR)
    const correctFixes = files.filter((f: string) =>
      f.startsWith(`${CHALLENGE_KEY}_`) && f.includes('_correct')
    )
    expect(correctFixes.length).to.equal(1)
    // The correct fix filename must contain the number 2
    expect(correctFixes[0]).to.include('_2_correct')
  })

  it('should have an info YAML file describing the fix explanations', () => {
    expect(fs.existsSync(`${FIXES_DIR}/${CHALLENGE_KEY}.info.yml`)).to.equal(true)
  })

  describe('fix #1 (regex blocklist — incorrect)', () => {
    it('should be marked as incorrect (no _correct suffix in filename)', () => {
      const files = fs.readdirSync(FIXES_DIR)
      const fix1 = files.find((f: string) => f === `${CHALLENGE_KEY}_1.ts`)
      expect(fix1).to.not.be.undefined
      expect(fix1).to.not.include('_correct')
    })
  })

  describe('fix #2 (parameterized query — correct)', () => {
    it('should use Sequelize replacements to parameterize the query', () => {
      const content = fs.readFileSync(`${FIXES_DIR}/${CHALLENGE_KEY}_2_correct.ts`).toString()
      expect(content).to.include('replacements')
      expect(content).to.include(':criteria')
    })

    it('should not use template-literal interpolation of criteria', () => {
      const content = fs.readFileSync(`${FIXES_DIR}/${CHALLENGE_KEY}_2_correct.ts`).toString()
      expect(content).to.not.match(/\$\{criteria\}/)
    })
  })

  describe('fix #3 (startsWith allowlist — incorrect)', () => {
    it('should be marked as incorrect (no _correct suffix in filename)', () => {
      const files = fs.readdirSync(FIXES_DIR)
      const fix3 = files.find((f: string) => f === `${CHALLENGE_KEY}_3.ts`)
      expect(fix3).to.not.be.undefined
      expect(fix3).to.not.include('_correct')
    })

    it('should still contain string interpolation making it vulnerable', () => {
      const content = fs.readFileSync(`${FIXES_DIR}/${CHALLENGE_KEY}_3.ts`).toString()
      // Fix 3 still uses interpolation — demonstrating that startsWith checks are insufficient
      expect(content).to.match(/\$\{criteria\}/)
    })
  })
})
