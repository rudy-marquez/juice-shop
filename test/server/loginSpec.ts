/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

/**
 * Unit tests verifying that the login route uses parameterized Sequelize bind
 * parameters instead of template-literal string interpolation for user input.
 *
 * CWE-89 SQL Injection (CVSS 9.7): The original code embedded req.body.email
 * and security.hash(req.body.password) directly into a SQL template literal,
 * allowing attackers to inject arbitrary SQL through either field.
 *
 * The fix replaces the unsafe template literal with Sequelize positional bind
 * parameters ($1 / $2) so user-supplied values never touch the query string.
 */
describe('login route', () => {
  let models: any
  let mockQueryResult: any
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    // Stub res helpers so the handler does not crash
    res = {
      json: sinon.stub(),
      status: sinon.stub(),
      send: sinon.stub(),
      __: sinon.stub().returns('Invalid email or password.')
    }
    res.status.returns(res) // allow chaining res.status(401).json(...)

    next = sinon.spy()

    // Default: no matching user (401 path)
    mockQueryResult = null

    // Stub models.sequelize.query to capture arguments
    models = require('../../models/index')
    sinon.stub(models.sequelize, 'query').resolves(mockQueryResult)
  })

  afterEach(() => {
    sinon.restore()
  })

  // ─── Parameterized-query shape ────────────────────────────────────────────

  describe('SQL injection prevention: parameterized query usage', () => {
    it('should call sequelize.query with a plain string (not a template literal with interpolated user data)', () => {
      req = { body: { email: 'test@example.com', password: 'secret' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      expect(models.sequelize.query).to.have.been.calledOnce
      const queryArg: string = models.sequelize.query.firstCall.args[0]

      // The query string must NOT contain the literal user-supplied email
      expect(queryArg).not.to.include('test@example.com')
      // The query string must NOT contain req.body.password (raw or hashed)
      expect(queryArg).not.to.include('secret')
    })

    it('should call sequelize.query with $1 and $2 bind placeholders', () => {
      req = { body: { email: 'user@juice-sh.op', password: 'hunter2' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      expect(models.sequelize.query).to.have.been.calledOnce
      const queryArg: string = models.sequelize.query.firstCall.args[0]

      expect(queryArg).to.include('$1')
      expect(queryArg).to.include('$2')
    })

    it('should pass a bind array as part of the options object', () => {
      req = { body: { email: 'user@juice-sh.op', password: 'hunter2' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      expect(models.sequelize.query).to.have.been.calledOnce
      const opts = models.sequelize.query.firstCall.args[1]

      expect(opts).to.have.property('bind')
      expect(opts.bind).to.be.an('array')
      expect(opts.bind).to.have.length(2)
    })

    it('should pass the email as the first bind parameter', () => {
      req = { body: { email: 'admin@juice-sh.op', password: 'anypass' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts.bind[0]).to.equal('admin@juice-sh.op')
    })

    it('should pass the hashed password (not the raw password) as the second bind parameter', () => {
      const security = require('../../lib/insecurity')
      req = { body: { email: 'admin@juice-sh.op', password: 'admin123' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      // The second bind value must equal the MD5 hash, never the plaintext
      expect(opts.bind[1]).to.equal(security.hash('admin123'))
      expect(opts.bind[1]).not.to.equal('admin123')
    })

    it('should use empty strings for undefined email and password in bind array', () => {
      req = { body: {} }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts.bind[0]).to.equal('')
    })
  })

  // ─── SQL injection attack payloads should NOT break parameterization ──────

  describe('SQL injection attack payloads are treated as data, not SQL', () => {
    it('should pass classic OR-1=1 payload as a literal bind value', () => {
      req = { body: { email: "' OR '1'='1", password: 'doesNotMatter' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      // The payload must land verbatim in the bind array, not in the SQL string
      expect(opts.bind[0]).to.equal("' OR '1'='1")

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).not.to.include("' OR '1'='1")
    })

    it('should pass a UNION SELECT injection payload as a literal bind value', () => {
      const payload = "' UNION SELECT * FROM Users--"
      req = { body: { email: payload, password: 'x' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts.bind[0]).to.equal(payload)

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).not.to.include('UNION SELECT')
    })

    it('should pass a comment-termination payload as a literal bind value', () => {
      const payload = "admin@juice-sh.op'--"
      req = { body: { email: payload, password: undefined } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts.bind[0]).to.equal(payload)
    })

    it('should pass a semicolon injection payload as a literal bind value', () => {
      req = { body: { email: "';", password: undefined } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts.bind[0]).to.equal("';")
    })
  })

  // ─── Query structure integrity ────────────────────────────────────────────

  describe('query structure', () => {
    it('should query the Users table', () => {
      req = { body: { email: 'a@b.com', password: 'pw' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).to.match(/SELECT \* FROM Users/i)
    })

    it('should filter by email using the $1 placeholder', () => {
      req = { body: { email: 'a@b.com', password: 'pw' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).to.match(/email\s*=\s*\$1/)
    })

    it('should filter by password using the $2 placeholder', () => {
      req = { body: { email: 'a@b.com', password: 'pw' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).to.match(/password\s*=\s*\$2/)
    })

    it('should filter out soft-deleted users (deletedAt IS NULL)', () => {
      req = { body: { email: 'a@b.com', password: 'pw' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const queryArg: string = models.sequelize.query.firstCall.args[0]
      expect(queryArg).to.include('deletedAt IS NULL')
    })

    it('should request a plain (single row) result', () => {
      req = { body: { email: 'a@b.com', password: 'pw' } }
      const login = require('../../routes/login')
      login()(req, res, next)

      const opts = models.sequelize.query.firstCall.args[1]
      expect(opts).to.have.property('plain', true)
    })
  })

  // ─── Response behaviour (no user found) ──────────────────────────────────

  describe('response when no matching user is found', () => {
    it('should respond with HTTP 401 when query returns null', (done) => {
      req = { body: { email: 'nobody@example.com', password: 'wrong' } }
      models.sequelize.query.resolves(null)

      const login = require('../../routes/login')
      login()(req, res, next)

      // Allow the promise chain to settle
      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })
  })
})
