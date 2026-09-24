/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Tests verifying that routes/login.ts uses Sequelize bind parameters
 * (parameterized queries) instead of unsafe SQL string interpolation.
 *
 * CWE-89 SQL Injection: The original code embedded req.body.email and
 * security.hash(req.body.password) directly into a SQL template literal,
 * allowing attackers to bypass authentication with payloads such as
 * "' OR 1=1--" in the email field.
 *
 * The fix uses Sequelize bind parameters ($1/$2) which are equivalent to
 * prepared statements and prevent any user-supplied data from being
 * interpreted as SQL syntax.
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('login route SQL injection remediation', () => {
  let models: any
  let queryStub: sinon.SinonStub
  let req: any
  let res: any
  let next: sinon.SinonSpy

  beforeEach(() => {
    models = require('../../models/index')
    queryStub = sinon.stub(models.sequelize, 'query')
    // Default: simulate no matching user (authentication fails)
    queryStub.returns(Promise.resolve(null))

    req = {
      body: { email: 'test@example.com', password: 'testpassword' },
      headers: {}
    }
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis(),
      send: sinon.spy(),
      __: (msg: string) => msg
    }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('parameterized query usage', () => {
    it('should call sequelize.query with a static SQL string (no template literal interpolation)', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(queryStub).to.have.been.calledOnce
        const sqlArg: string = queryStub.firstCall.args[0]
        // The SQL string must be a static string — no ${ template expressions
        expect(sqlArg).to.be.a('string')
        expect(sqlArg).to.not.include('${')
        done()
      })
    })

    it('should pass a bind array as the second argument to sequelize.query', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(queryStub).to.have.been.calledOnce
        const optionsArg = queryStub.firstCall.args[1]
        expect(optionsArg).to.have.property('bind')
        expect(optionsArg.bind).to.be.an('array')
        expect(optionsArg.bind).to.have.length(2)
        done()
      })
    })

    it('should use positional bind placeholders $1 and $2 in the SQL string', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        expect(sqlArg).to.include('$1')
        expect(sqlArg).to.include('$2')
        done()
      })
    })

    it('should place the email value as the first bind parameter', (done) => {
      req.body.email = 'admin@juice-sh.op'
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const optionsArg = queryStub.firstCall.args[1]
        expect(optionsArg.bind[0]).to.equal('admin@juice-sh.op')
        done()
      })
    })

    it('should place the hashed password as the second bind parameter (not the raw password)', (done) => {
      const security = require('../../lib/insecurity')
      const rawPassword = 'admin123'
      req.body.password = rawPassword
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const optionsArg = queryStub.firstCall.args[1]
        // The raw password must NOT appear in the bind array
        expect(optionsArg.bind[1]).to.not.equal(rawPassword)
        // The hashed password must appear instead
        expect(optionsArg.bind[1]).to.equal(security.hash(rawPassword))
        done()
      })
    })

    it('should default empty string for missing email rather than embedding undefined in SQL', (done) => {
      req.body.email = undefined
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const optionsArg = queryStub.firstCall.args[1]
        expect(optionsArg.bind[0]).to.equal('')
        done()
      })
    })

    it('should default empty string for missing password rather than embedding undefined in SQL', (done) => {
      req.body.password = undefined
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const optionsArg = queryStub.firstCall.args[1]
        // bind[1] is the hashed empty string, not undefined
        expect(optionsArg.bind[1]).to.be.a('string')
        expect(optionsArg.bind[1]).to.not.equal(undefined)
        done()
      })
    })
  })

  describe('SQL injection payloads are treated as literal data', () => {
    it('should pass SQL injection email payload as a bind value, not embedded in SQL', (done) => {
      req.body.email = "' OR 1=1--"
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        const optionsArg = queryStub.firstCall.args[1]
        // The injection payload must NOT appear in the SQL string itself
        expect(sqlArg).to.not.include("' OR 1=1--")
        // It must appear as a bind parameter value instead
        expect(optionsArg.bind[0]).to.equal("' OR 1=1--")
        done()
      })
    })

    it('should pass UNION SELECT injection payload as a bind value, not embedded in SQL', (done) => {
      req.body.email = "' UNION SELECT * FROM Users--"
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        const optionsArg = queryStub.firstCall.args[1]
        expect(sqlArg).to.not.include('UNION SELECT')
        expect(optionsArg.bind[0]).to.equal("' UNION SELECT * FROM Users--")
        done()
      })
    })

    it('should pass comment-based SQL injection payload as a bind value', (done) => {
      req.body.email = "admin@juice-sh.op'--"
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        const optionsArg = queryStub.firstCall.args[1]
        // The SQL comment sequence must not appear in the raw SQL string
        expect(sqlArg).to.not.include("'--")
        // The payload must be bound as data
        expect(optionsArg.bind[0]).to.equal("admin@juice-sh.op'--")
        done()
      })
    })

    it('should pass boolean-based injection payload in password field as bound data', (done) => {
      req.body.password = "' OR '1'='1"
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        // The raw injection string must not appear in the SQL
        expect(sqlArg).to.not.include("' OR '1'='1")
        done()
      })
    })
  })

  describe('query structure preservation', () => {
    it('should query the Users table', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        expect(sqlArg).to.match(/SELECT \* FROM Users/)
        done()
      })
    })

    it('should filter on both email and password columns', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        expect(sqlArg).to.match(/email\s*=\s*\$1/)
        expect(sqlArg).to.match(/password\s*=\s*\$2/)
        done()
      })
    })

    it('should exclude soft-deleted users via deletedAt IS NULL', (done) => {
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        const sqlArg: string = queryStub.firstCall.args[0]
        expect(sqlArg).to.include('deletedAt IS NULL')
        done()
      })
    })
  })

  describe('authentication response behaviour', () => {
    it('should return 401 when no user matches the provided credentials', (done) => {
      queryStub.returns(Promise.resolve(null))
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })

    it('should propagate database errors to next() error handler', (done) => {
      const dbError = new Error('SQLITE_ERROR: near "OR": syntax error')
      queryStub.returns(Promise.reject(dbError))
      const login = require('../../routes/login')
      login()(req, res, next)

      setImmediate(() => {
        // Give the promise chain time to settle
        setImmediate(() => {
          expect(next).to.have.been.calledWith(dbError)
          done()
        })
      })
    })
  })
})
