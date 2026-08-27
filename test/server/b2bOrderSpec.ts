/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('b2bOrder', () => {
  const createB2bOrder = require('../../routes/b2bOrder')
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { body: {} }
    res = { json: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  describe('safe JSON deserialization (CWE-502 remediation)', () => {
    it('rejects code execution payloads — infinite loop — by calling next with error', () => {
      req.body.orderLinesData = '(function dos() { while(true); })()'

      createB2bOrder()(req, res, next)

      // JSON.parse throws a SyntaxError for non-JSON input; next is called with the error
      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
      expect(res.json).to.not.have.been.called
    })

    it('rejects ReDoS regex spin-up payloads — calls next with error', () => {
      req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

      createB2bOrder()(req, res, next)

      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
      expect(res.json).to.not.have.been.called
    })

    it('rejects process.exit() sandbox escape payload — calls next with error', () => {
      req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

      createB2bOrder()(req, res, next)

      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
      expect(res.json).to.not.have.been.called
    })

    it('rejects eval/exec injection payloads — calls next with error', () => {
      req.body.orderLinesData = 'eval("require(\'child_process\').execSync(\'id\')")'

      createB2bOrder()(req, res, next)

      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
      expect(res.json).to.not.have.been.called
    })

    it('accepts valid JSON order as documented in Swagger and returns order response', () => {
      req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

      createB2bOrder()(req, res, next)

      expect(next).to.not.have.been.called
      expect(res.json).to.have.been.calledOnce
    })

    it('accepts arbitrary valid JSON and returns order response', () => {
      req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

      createB2bOrder()(req, res, next)

      expect(next).to.not.have.been.called
      expect(res.json).to.have.been.calledOnce
    })

    it('rejects malformed / broken JSON — calls next with SyntaxError', () => {
      req.body.orderLinesData = '{ "productId: 28'

      createB2bOrder()(req, res, next)

      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
      expect(res.json).to.not.have.been.called
    })

    it('uses empty string as default when orderLinesData is absent — calls next with SyntaxError', () => {
      // empty string is not valid JSON, so JSON.parse throws
      req.body = {}

      createB2bOrder()(req, res, next)

      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(SyntaxError)
    })

    it('response includes cid echoed from request body', () => {
      req.body.cid = 'test-customer-001'
      req.body.orderLinesData = '{"productId": 5, "quantity": 1}'

      createB2bOrder()(req, res, next)

      expect(res.json).to.have.been.calledOnce
      const response = res.json.firstCall.args[0]
      expect(response).to.have.property('cid', 'test-customer-001')
    })

    it('response includes orderNo and paymentDue fields', () => {
      req.body.orderLinesData = '{"productId": 5, "quantity": 1}'

      createB2bOrder()(req, res, next)

      expect(res.json).to.have.been.calledOnce
      const response = res.json.firstCall.args[0]
      expect(response).to.have.property('orderNo').that.is.a('string')
      expect(response).to.have.property('paymentDue').that.is.a('string')
    })

    it('accepts a JSON array as orderLinesData', () => {
      req.body.orderLinesData = '[{"productId": 1, "quantity": 2}, {"productId": 3, "quantity": 4}]'

      createB2bOrder()(req, res, next)

      expect(next).to.not.have.been.called
      expect(res.json).to.have.been.calledOnce
    })
  })
})
