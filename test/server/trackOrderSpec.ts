/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('trackOrder', () => {
  const trackOrder = require('../../routes/trackOrder')
  const challenges = require('../../data/datacache').challenges
  let req: any
  let res: any
  let save: any
  let mongoDB: any
  let findStub: sinon.SinonStub

  beforeEach(() => {
    req = { params: {} }
    res = { json: sinon.spy(), status: sinon.stub().returns({ json: sinon.spy() }) }
    save = () => ({ then () { } })

    // Stub db.orders.find to control what the MongoDB collection returns
    mongoDB = require('../../data/mongodb')
    findStub = sinon.stub(mongoDB.orders, 'find')
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('NoSQL injection prevention', () => {
    it('should pass the order id as a plain field equality value, not inside a $where expression', () => {
      const orderId = 'test-order-123'
      findStub.returns(Promise.resolve([{ orderId }]))
      req.params.id = orderId

      trackOrder()(req, res)

      // The find call must NOT use the $where operator with string interpolation
      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.deep.equal({ orderId })
    })

    it('should reject NoSQL injection payload that attempts JavaScript execution via $where', () => {
      // A classic NoSQL injection payload that would exploit $where: "this.orderId === '...' || '1'==='1'"
      const injectionPayload = "' || '1'==='1"
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      trackOrder()(req, res)

      // The find call must use a safe field equality query, not $where
      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      // The payload is used as a literal string value, not injected into JS code
      expect(queryArg).to.have.property('orderId')
    })

    it('should reject NoSQL injection payload with function call attempt', () => {
      // Payload designed to exploit $where: "this.orderId === '...' ; return true //"
      const injectionPayload = "anything'; return true //"
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      trackOrder()(req, res)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('orderId')
    })

    it('should not allow query to match all orders via always-true injection payload', () => {
      // This injection payload would have matched ALL orders with the old $where approach.
      // With the safe field equality query it is treated as a literal orderId string.
      const injectionPayload = "' || 1===1 || '"
      // Simulate the safe query returning no results (no order has this literal id)
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      trackOrder()(req, res)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.deep.equal({ orderId: injectionPayload })
    })
  })

  describe('normal order tracking', () => {
    it('should return order details for a valid order id', (done) => {
      const orderId = 'valid-order-456'
      const mockOrder = { orderId, totalPrice: 9.99 }
      findStub.returns(Promise.resolve([mockOrder]))
      req.params.id = orderId

      trackOrder()(req, res)

      setImmediate(() => {
        expect(findStub).to.have.been.calledWith({ orderId })
        expect(res.json).to.have.been.called
        done()
      })
    })

    it('should return a placeholder when no order is found for the given id', (done) => {
      const orderId = 'nonexistent-order'
      findStub.returns(Promise.resolve([]))
      req.params.id = orderId

      trackOrder()(req, res)

      setImmediate(() => {
        expect(findStub).to.have.been.calledWith({ orderId })
        expect(res.json).to.have.been.called
        const jsonArg = (res.json as sinon.SinonSpy).firstCall.args[0]
        // Fallback placeholder contains the queried orderId
        expect(jsonArg.data[0]).to.deep.equal({ orderId })
        done()
      })
    })

    it('should return 400 error when the database query fails', (done) => {
      findStub.returns(Promise.reject(new Error('DB error')))
      req.params.id = 'some-order'

      trackOrder()(req, res)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(400)
        done()
      })
    })
  })

  describe('challenge flag tracking', () => {
    it('should not solve "noSqlOrdersChallenge" when query returns only one order', (done) => {
      challenges.noSqlOrdersChallenge = { solved: false, save }
      findStub.returns(Promise.resolve([{ orderId: 'order-001' }]))
      req.params.id = 'order-001'

      trackOrder()(req, res)

      setImmediate(() => {
        expect(challenges.noSqlOrdersChallenge.solved).to.equal(false)
        done()
      })
    })
  })
})
