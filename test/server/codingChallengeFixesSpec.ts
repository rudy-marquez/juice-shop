/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import chai = require('chai')
import fs from 'graceful-fs'
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('codingChallengeFixes', () => {
  let codingChallenges: string[]
  before(async () => {
    codingChallenges = await retrieveChallengesWithCodeSnippet()
  })

  it('should have a correct fix for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      expect(fixes.correct, `Coding challenge ${challenge} does not have a correct fix file`).to.be.greaterThan(-1)
    }
  })

  it('should have a total of three or more fix options for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      expect(fixes.fixes.length, `Coding challenge ${challenge} does not have enough fix option files`).to.be.greaterThanOrEqual(3)
    }
  })

  it('should have an info YAML file for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      expect(fs.existsSync('./data/static/codefixes/' + challenge + '.info.yml'), `Coding challenge ${challenge} does not have an info YAML file`).to.equal(true)
    }
  })
})

describe('unionSqlInjectionChallenge fix option 3', () => {
  const fixFilePath = './data/static/codefixes/unionSqlInjectionChallenge_3.ts'

  it('fix file should exist', () => {
    expect(fs.existsSync(fixFilePath)).to.equal(true)
  })

  it('should not contain string-interpolated user input in SQL query (no template literal injection)', () => {
    const fixContent = fs.readFileSync(fixFilePath, 'utf8')
    // Parameterized queries must not embed the criteria variable directly via template literal
    expect(fixContent).to.not.match(/`[^`]*\$\{criteria\}[^`]*`/)
  })

  it('should use Sequelize parameterized replacements to prevent SQL injection', () => {
    const fixContent = fs.readFileSync(fixFilePath, 'utf8')
    // The fix must pass a replacements object to sequelize.query()
    expect(fixContent).to.match(/replacements\s*:\s*\{/)
  })

  it('should use a named placeholder for criteria in the SQL query', () => {
    const fixContent = fs.readFileSync(fixFilePath, 'utf8')
    // The SQL query must reference criteria as a named bound parameter (:criteria)
    expect(fixContent).to.match(/:criteria/)
  })

  it('should still call sequelize.query with a parameterized SQL string', () => {
    const fixContent = fs.readFileSync(fixFilePath, 'utf8')
    expect(fixContent).to.include('sequelize.query(')
    expect(fixContent).to.include('SELECT * FROM Products WHERE')
  })
})
