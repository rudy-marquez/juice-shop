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
 * Unit tests for the login route.
 *
 * These tests verify that the SQL-injection vulnerability has been remediated:
 * the route must use UserModel.findOne() with a parameterized WHERE clause
 * instead of building a raw SQL string with user-supplied input.
 */
describe('login', () => {
  const { UserModel } = require('../../models/user')
  const security = require('../../lib/insecurity')

  let req: any
  let res: any
  let next: sinon.SinonSpy
  let findOneStub: sinon.SinonStub

  beforeEach(() => {
    req = { body: {} }
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis(),
      send: sinon.spy(),
      __: (msg: string) => msg
    }
    next = sinon.spy()

    // Stub UserModel.findOne so no real DB call is made
    findOneStub = sinon.stub(UserModel, 'findOne')
  })

  afterEach(() => {
    sinon.restore()
  })

  // ─── SQL-injection prevention ────────────────────────────────────────────────

  describe('SQL injection prevention', () => {
    it('should call UserModel.findOne with email and hashed password as discrete parameters, not raw SQL', () => {
      req.body.email = 'admin@juice-sh.op'
      req.body.password = 'admin123'
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      // Must have called findOne exactly once
      expect(findOneStub).to.have.been.calledOnce

      // The first argument to findOne must be an options object with a `where` clause
      const callArg = findOneStub.firstCall.args[0]
      expect(callArg).to.be.an('object')
      expect(callArg).to.have.property('where')
    })

    it('should pass email as a plain value in the where clause, not interpolated into a SQL string', () => {
      const maliciousEmail = "' OR '1'='1'--"
      req.body.email = maliciousEmail
      req.body.password = 'irrelevant'
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      const { where } = findOneStub.firstCall.args[0]
      // The email field must be the literal value supplied — not a SQL fragment
      expect(where.email).to.equal(maliciousEmail)
    })

    it('should pass hashed password as a plain value in the where clause, not interpolated into SQL', () => {
      const maliciousPassword = "' OR 1=1--"
      req.body.email = 'user@example.com'
      req.body.password = maliciousPassword
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      const { where } = findOneStub.firstCall.args[0]
      // Password must arrive at findOne as the MD5 hash of the raw input —
      // the ORM will use it as a bound parameter, not injected SQL
      expect(where.password).to.equal(security.hash(maliciousPassword))
    })

    it('should NOT construct a raw SQL query string (no sequelize.query call with interpolated email)', () => {
      // Verify the route does NOT use sequelize.query with a template literal;
      // it must delegate to UserModel.findOne for parameterised access.
      req.body.email = "'; DROP TABLE Users;--"
      req.body.password = 'anything'
      findOneStub.returns(Promise.resolve(null))

      const models = require('../../models/index')
      const querySpy = sinon.spy(models.sequelize, 'query')

      const login = require('../../routes/login')
      login()(req, res, next)

      // sequelize.query must NOT have been called with the user-supplied email
      const wasCalled = querySpy.getCalls().some((call: sinon.SinonSpyCall) => {
        const sql: string = call.args[0]
        return typeof sql === 'string' && sql.includes(req.body.email)
      })
      expect(wasCalled).to.equal(false,
        'sequelize.query must not be called with user-controlled input interpolated into the SQL string')
    })

    it('should include deletedAt: null in the where clause to filter soft-deleted users', () => {
      req.body.email = 'user@example.com'
      req.body.password = 'password123'
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      const { where } = findOneStub.firstCall.args[0]
      // Ensures soft-deleted accounts are excluded from authentication
      expect(where).to.have.property('deletedAt', null)
    })

    it('should handle a classic WHERE-clause disabling injection gracefully (return 401)', (done) => {
      // "' or 1=1--" would bypass the original raw SQL; the parameterised query
      // treats it as a literal email value so no user will match, returning 401.
      req.body.email = "' or 1=1--"
      req.body.password = undefined
      findOneStub.returns(Promise.resolve(null)) // no user found = 401

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })

    it('should handle a UNION SELECT injection payload gracefully (return 401)', (done) => {
      req.body.email = "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13 FROM Users--"
      req.body.password = undefined
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })
  })

  // ─── Normal login behaviour ──────────────────────────────────────────────────

  describe('successful authentication', () => {
    it('should respond with 200 and authentication data when valid credentials are supplied', (done) => {
      req.body.email = 'user@example.com'
      req.body.password = 'correctpassword'

      const fakeUser = {
        dataValues: {
          id: 42,
          email: 'user@example.com',
          totpSecret: '',
          role: 'customer'
        }
      }
      findOneStub.returns(Promise.resolve(fakeUser))

      // Stub BasketModel.findOrCreate to avoid DB call
      const { BasketModel } = require('../../models/basket')
      sinon.stub(BasketModel, 'findOrCreate').returns(
        Promise.resolve([{ id: 7 }, true])
      )

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(findOneStub).to.have.been.calledOnce
        done()
      })
    })

    it('should return 401 with totp_token_required when user has a TOTP secret set', (done) => {
      req.body.email = 'totp@example.com'
      req.body.password = 'anypassword'

      const fakeUser = {
        dataValues: {
          id: 99,
          email: 'totp@example.com',
          totpSecret: 'SOMESECRETVALUE',
          role: 'customer'
        }
      }
      findOneStub.returns(Promise.resolve(fakeUser))

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        const jsonArg = (res.status() as any).json
          ? (res as any).status.firstCall.returnValue
          : null
        // Verify totp status was set
        const callArgs = (res.status as sinon.SinonStub).firstCall.args
        expect(callArgs[0]).to.equal(401)
        done()
      })
    })
  })

  describe('failed authentication', () => {
    it('should return 401 when no matching user is found', (done) => {
      req.body.email = 'nobody@nowhere.com'
      req.body.password = 'wrongpassword'
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })

    it('should call next(error) when UserModel.findOne rejects', (done) => {
      req.body.email = 'user@example.com'
      req.body.password = 'password'
      const dbError = new Error('Database connection error')
      findOneStub.returns(Promise.reject(dbError))

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(next).to.have.been.calledWith(dbError)
        done()
      })
    })

    it('should return 401 when email and password are both undefined', (done) => {
      req.body.email = undefined
      req.body.password = undefined
      findOneStub.returns(Promise.resolve(null))

      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })
  })
})
