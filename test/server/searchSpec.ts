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

describe('search', () => {
  const models = require('../../models/index')
  let req: any
  let res: any
  let next: any
  let queryStub: sinon.SinonStub

  beforeEach(() => {
    req = { query: {}, __: (x: string) => x }
    res = { json: sinon.spy(), status: sinon.stub().returnsThis() }
    next = sinon.spy()
    // Stub models.sequelize.query to observe how it is called
    queryStub = sinon.stub(models.sequelize, 'query').resolves([])
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should use parameterized query (replacements) instead of string interpolation', () => {
    req.query.q = 'apple'
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    expect(queryStub).to.have.been.calledOnce
    const [sql, options] = queryStub.firstCall.args
    // The SQL must use a named placeholder, not the raw value
    expect(sql).to.not.include('apple')
    expect(sql).to.include(':searchCriteria')
    // The replacement value must be present in the options object
    expect(options).to.have.property('replacements')
    expect(options.replacements).to.have.property('searchCriteria', '%apple%')
  })

  it('should not interpolate SQL-injection payload into query string', () => {
    req.query.q = "' OR '1'='1"
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    // Raw injection payload must NOT appear in the SQL string itself
    expect(sql).to.not.include("' OR '1'='1")
    // The payload must be safely passed as a replacement value
    expect(options.replacements.searchCriteria).to.include("' OR '1'='1")
  })

  it('should not interpolate UNION SELECT injection payload into query string', () => {
    req.query.q = "')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.not.include('UNION SELECT')
    expect(options.replacements.searchCriteria).to.include('UNION SELECT')
  })

  it('should handle empty search query safely', () => {
    req.query.q = ''
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.include(':searchCriteria')
    expect(options.replacements.searchCriteria).to.equal('%%')
  })

  it('should handle undefined search query safely', () => {
    req.query.q = undefined
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [sql, options] = queryStub.firstCall.args
    expect(sql).to.include(':searchCriteria')
    expect(options.replacements).to.have.property('searchCriteria')
  })

  it('should truncate search criteria longer than 200 characters', () => {
    req.query.q = 'a'.repeat(300)
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [, options] = queryStub.firstCall.args
    // After wrapping in %, length should be 202 (200 chars + 2 percent signs)
    expect(options.replacements.searchCriteria.length).to.equal(202)
  })

  it('should use QueryTypes.SELECT so results are returned as an array directly', () => {
    req.query.q = 'juice'
    queryStub.resolves([{ id: 1, name: 'Apple Juice', description: 'Fresh' }])
    const searchProducts = require('../../routes/search')

    searchProducts()(req, res, next)

    const [, options] = queryStub.firstCall.args
    // type option must be set to QueryTypes.SELECT so results are returned as a plain array
    expect(options).to.have.property('type')
    expect(options.type).to.equal(QueryTypes.SELECT)
  })
})
