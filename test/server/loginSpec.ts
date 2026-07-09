/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
import { QueryTypes } from 'sequelize'
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('login', () => {
  const models = require('../../models/index')
  const security = require('../../lib/insecurity')
  let req: any
  let res: any
  let next: any
  let queryStub: sinon.SinonStub

  beforeEach(() => {
    req = { body: {}, headers: {}, __: (x: string) => x }
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis(),
      send: sinon.spy(),
      __: (x: string) => x
    }
    next = sinon.spy()
    // Stub models.sequelize.query to observe how it is called
    queryStub = sinon.stub(models.sequelize, 'query').resolves(null)
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should use parameterized query with named replacements for email', () => {
    req.body.email = 'test@example.com'
    req.body.password = 'password123'
    const login = require('../../routes/login')

    login()(req, res, next)

    expect(queryStub).to.have.been.calledOnce
    const [sql, options] = queryStub.firstCall.args
    // The raw email value must NOT be interpolated into the SQL string
    expect(sql).to.not.include('test@example.com')
    expect(sql).to.include(':email')
    expect(options).to.have.property('replacements')
    expect(options.replacements).to.have.property('email', 'test@example.com')
  })

  it('should use parameterized query with named replacements for password hash', () => {
    req.body.email = 'test@example.com'
    req.body.password = 'password123'
    const login = require('../../routes/login')

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include('password123')
    expect(sql).to.include(':password')
    expect(options.replacements).to.have.property('password', security.hash('password123'))
  })

  it('should not interpolate SQL injection payload (OR 1=1) into query string', () => {
    req.body.email = "' OR '1'='1'--"
    req.body.password = 'anything'
    const login = require('../../routes/login')

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    // Injection payload must NOT appear literally in the SQL text
    expect(sql).to.not.include("' OR '1'='1'--")
    // It must be safely stored as a replacement value
    expect(options.replacements.email).to.include("' OR '1'='1'--")
  })

  it('should not interpolate UNION SELECT injection payload into query string', () => {
    req.body.email = "' UNION SELECT * FROM Users--"
    req.body.password = ''
    const login = require('../../routes/login')

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include('UNION SELECT')
    expect(options.replacements.email).to.include('UNION SELECT')
  })

  it('should not interpolate comment-based bypass payload into query string', () => {
    req.body.email = "admin@juice-sh.op'--"
    req.body.password = ''
    const login = require('../../routes/login')

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include("admin@juice-sh.op'--")
    expect(options.replacements.email).to.include("admin@juice-sh.op'--")
  })

  it('should safely handle undefined email by defaulting to empty string', () => {
    req.body.email = undefined
    req.body.password = undefined
    const login = require('../../routes/login')

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.include(':email')
    expect(options.replacements.email).to.equal('')
  })

  it('should use QueryTypes.SELECT so result is returned directly (plain: true compatibility)', () => {
    req.body.email = 'user@example.com'
    req.body.password = 'pass'
    const login = require('../../routes/login')

    login()(req, res, next)

    const [, options] = queryStub.firstCall.args
    expect(options).to.have.property('type')
    expect(options.type).to.equal(QueryTypes.SELECT)
    expect(options).to.have.property('plain', true)
  })
})
