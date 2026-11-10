/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('login SQL injection protection', () => {
  const models = require('../../models/index')
  const login = require('../../routes/login')
  const security = require('../../lib/insecurity')
  let req: any
  let res: any
  let next: any
  let queryStub: sinon.SinonStub

  beforeEach(() => {
    req = { body: {} }
    res = { status: sinon.stub().returnsThis(), json: sinon.spy(), send: sinon.spy(), __: (s: string) => s }
    next = sinon.spy()
    queryStub = sinon.stub(models.sequelize, 'query').resolves(null)
  })

  afterEach(() => {
    queryStub.restore()
  })

  it('should pass a malicious email as a bind parameter and not embed it into the SQL text', async () => {
    const payload = "' OR true --"
    req.body = { email: payload, password: 'secret' }

    login()(req, res, next)
    await new Promise(resolve => setImmediate(resolve))

    expect(queryStub).to.have.been.calledOnce
    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include(payload)
    expect(sql).to.include('email = $1')
    expect(sql).to.include('password = $2')
    expect(options.bind[0]).to.equal(payload)
  })

  it('should pass the hashed password as a bind parameter', async () => {
    const payload = "x' OR '1'='1"
    req.body = { email: 'jim@juice-sh.op', password: payload }

    login()(req, res, next)
    await new Promise(resolve => setImmediate(resolve))

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include(payload)
    expect(sql).to.not.include(security.hash(payload))
    expect(options.bind).to.deep.equal(['jim@juice-sh.op', security.hash(payload)])
  })

  it('should fall back to empty strings when email and password are missing', async () => {
    login()(req, res, next)
    await new Promise(resolve => setImmediate(resolve))

    const [, options] = queryStub.firstCall.args
    expect(options.bind).to.deep.equal(['', security.hash('')])
  })

  it('should respond with 401 when no user matches', async () => {
    req.body = { email: "' OR true --", password: 'x' }

    login()(req, res, next)
    await new Promise(resolve => setImmediate(resolve))

    expect(res.status).to.have.been.calledWith(401)
  })
})
