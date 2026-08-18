/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('login', () => {
  const models = require('../../models/index')
  let req: any
  let res: any
  let next: any
  let queryStub: sinon.SinonStub

  beforeEach(() => {
    req = {
      body: {},
      connection: { remoteAddress: '127.0.0.1' },
      headers: {}
    }
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis(),
      send: sinon.spy(),
      __: (key: string) => key
    }
    next = sinon.spy()

    // Stub sequelize.query to control what the database returns
    queryStub = sinon.stub(models.sequelize, 'query')
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('SQL injection prevention — parameterized query', () => {
    it('should call sequelize.query with a parameterized query string (no interpolation)', () => {
      // Arrange: query resolves with no matching user
      queryStub.returns(Promise.resolve(null))
      req.body.email = 'admin@juice-sh.op'
      req.body.password = 'admin123'

      // Act
      require('../../routes/login')()(req, res, next)

      // Assert: the raw SQL must use named placeholders, not string interpolation
      expect(queryStub).to.have.been.calledOnce
      const sqlArg: string = queryStub.firstCall.args[0]
      expect(sqlArg).to.be.a('string')
      expect(sqlArg).to.include(':email')
      expect(sqlArg).to.include(':password')
      // The user-controlled email must NOT appear literally in the SQL string
      expect(sqlArg).to.not.include('admin@juice-sh.op')
    })

    it('should pass email and password values via the replacements option, not in the SQL string', () => {
      queryStub.returns(Promise.resolve(null))
      req.body.email = 'user@example.com'
      req.body.password = 'somepassword'

      require('../../routes/login')()(req, res, next)

      expect(queryStub).to.have.been.calledOnce
      const opts: any = queryStub.firstCall.args[1]
      // The driver-level replacements object must carry the user-supplied value
      expect(opts).to.have.property('replacements')
      expect(opts.replacements).to.have.property('email', 'user@example.com')
    })

    it('should not embed SQL injection payload directly in the query string', () => {
      queryStub.returns(Promise.resolve(null))
      // Classic SQL injection bypass: attempts to comment out the password check
      const injectionPayload = "' OR '1'='1'--"
      req.body.email = injectionPayload
      req.body.password = ''

      require('../../routes/login')()(req, res, next)

      expect(queryStub).to.have.been.calledOnce
      const sqlArg: string = queryStub.firstCall.args[0]
      // The injection string must NOT appear in the SQL template itself
      expect(sqlArg).to.not.include(injectionPayload)
      expect(sqlArg).to.not.include("' OR '1'='1'--")
      // It must instead appear in the replacements binding
      const opts: any = queryStub.firstCall.args[1]
      expect(opts.replacements.email).to.equal(injectionPayload)
    })

    it('should not embed UNION SELECT injection payload in the query string', () => {
      queryStub.returns(Promise.resolve(null))
      const unionPayload = "' UNION SELECT * FROM Users--"
      req.body.email = unionPayload
      req.body.password = 'whatever'

      require('../../routes/login')()(req, res, next)

      const sqlArg: string = queryStub.firstCall.args[0]
      expect(sqlArg).to.not.include('UNION SELECT')
      const opts: any = queryStub.firstCall.args[1]
      expect(opts.replacements.email).to.equal(unionPayload)
    })

    it('should not embed WHERE-clause disabling payload in the query string', () => {
      queryStub.returns(Promise.resolve(null))
      const whereBypassPayload = "' or 1=1--"
      req.body.email = whereBypassPayload
      req.body.password = undefined

      require('../../routes/login')()(req, res, next)

      const sqlArg: string = queryStub.firstCall.args[0]
      expect(sqlArg).to.not.include('or 1=1')
      const opts: any = queryStub.firstCall.args[1]
      expect(opts.replacements.email).to.equal(whereBypassPayload)
    })

    it('should pass empty string for missing email via replacements', () => {
      queryStub.returns(Promise.resolve(null))
      req.body.email = undefined
      req.body.password = undefined

      require('../../routes/login')()(req, res, next)

      const opts: any = queryStub.firstCall.args[1]
      expect(opts.replacements).to.have.property('email', '')
    })

    it('should include the model and plain options alongside replacements', () => {
      queryStub.returns(Promise.resolve(null))
      req.body.email = 'test@test.com'
      req.body.password = 'test'

      require('../../routes/login')()(req, res, next)

      const opts: any = queryStub.firstCall.args[1]
      expect(opts).to.have.property('replacements')
      expect(opts).to.have.property('model')
      expect(opts).to.have.property('plain', true)
    })

    it('should return 401 when no user is found (query resolves to null)', (done) => {
      queryStub.returns(Promise.resolve(null))
      req.body.email = 'nonexistent@example.com'
      req.body.password = 'wrongpassword'

      require('../../routes/login')()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(401)
        done()
      })
    })

    it('should call next with an error when the database query rejects', (done) => {
      queryStub.returns(Promise.reject(new Error('Database connection error')))
      req.body.email = 'any@example.com'
      req.body.password = 'anypassword'

      require('../../routes/login')()(req, res, next)

      setImmediate(() => {
        expect(next).to.have.been.calledOnce
        expect(next.firstCall.args[0]).to.be.instanceOf(Error)
        done()
      })
    })
  })
})
