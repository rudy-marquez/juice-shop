/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('showProductReviews', () => {
  const productReviews = require('../../routes/showProductReviews')
  const challenges = require('../../data/datacache').challenges
  let req: any
  let res: any
  let next: any
  let save: any
  let mongoDB: any
  let findStub: sinon.SinonStub

  beforeEach(() => {
    req = { params: {}, headers: {} }
    res = { json: sinon.spy(), status: sinon.stub().returns({ json: sinon.spy() }) }
    next = sinon.spy()
    save = () => ({ then () { } })

    // Stub db.reviews.find to control what the MongoDB collection returns
    mongoDB = require('../../data/mongodb')
    findStub = sinon.stub(mongoDB.reviews, 'find')
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('NoSQL injection prevention', () => {
    it('should use a safe field equality query instead of $where string concatenation', () => {
      const productId = '1'
      findStub.returns(Promise.resolve([]))
      req.params.id = productId

      productReviews()(req, res, next)

      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      // Must NOT use the $where operator which allows JS injection
      expect(queryArg).to.not.have.property('$where')
      // Must use a safe field equality query
      expect(queryArg).to.have.property('product')
    })

    it('should treat a NoSQL sleep injection payload as a literal field value, not executable JS', () => {
      // Classic NoSQL injection that exploits $where: "this.product == sleep(2000)"
      const injectionPayload = 'sleep(2000)'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      productReviews()(req, res, next)

      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      // Must NOT use $where — that would execute the sleep() call as JS
      expect(queryArg).to.not.have.property('$where')
      // The payload must be passed as a literal string value, not JS code
      expect(queryArg).to.have.property('product')
    })

    it('should not allow always-true injection payload to bypass product filter', () => {
      // Payload that would return all reviews if injected into $where:
      // "this.product == 1 || true"
      const injectionPayload = '1 || true'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      productReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })

    it('should not allow object injection with $gt operator as product id', () => {
      // Attacker tries to pass a MongoDB query operator object
      const injectionPayload = '1; return true //'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      productReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })

    it('should not construct the query using string concatenation with the $where operator', () => {
      const productId = '42'
      findStub.returns(Promise.resolve([]))
      req.params.id = productId

      productReviews()(req, res, next)

      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      // Ensure the query does not contain any string that starts with 'this.product =='
      // which would indicate $where string concatenation is still in use
      if (queryArg.$where) {
        expect(queryArg.$where).to.not.include('this.product ==')
      }
      expect(queryArg).to.not.have.property('$where')
    })
  })

  describe('normal product review retrieval', () => {
    it('should query the reviews collection by product field equality', (done) => {
      const productId = '1'
      const mockReviews = [
        { product: 1, message: 'Great product!', author: 'user@example.com', likedBy: [] },
        { product: 1, message: 'Love it!', author: 'other@example.com', likedBy: [] }
      ]
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = productId

      productReviews()(req, res, next)

      setImmediate(() => {
        expect(findStub).to.have.been.calledOnce
        const queryArg = findStub.firstCall.args[0]
        expect(queryArg).to.have.property('product')
        expect(res.json).to.have.been.called
        done()
      })
    })

    it('should return JSON response when reviews are found', (done) => {
      const mockReviews = [
        { product: 2, message: 'Nice!', author: 'user@test.com', likedBy: [] }
      ]
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = '2'

      productReviews()(req, res, next)

      setImmediate(() => {
        expect(res.json).to.have.been.called
        const responseArg = (res.json as sinon.SinonSpy).firstCall.args[0]
        expect(responseArg).to.have.property('status', 'success')
        done()
      })
    })

    it('should return 400 error when the database query fails', (done) => {
      findStub.returns(Promise.reject(new Error('DB error')))
      req.params.id = '1'

      productReviews()(req, res, next)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(400)
        done()
      })
    })

    it('should return an empty data array when no reviews exist for the product', (done) => {
      findStub.returns(Promise.resolve([]))
      req.params.id = '999'

      productReviews()(req, res, next)

      setImmediate(() => {
        expect(res.json).to.have.been.called
        done()
      })
    })
  })

  describe('challenge tracking', () => {
    it('should not solve "noSqlCommandChallenge" when query completes in normal time', (done) => {
      challenges.noSqlCommandChallenge = { solved: false, save }
      findStub.returns(Promise.resolve([]))
      req.params.id = '1'

      productReviews()(req, res, next)

      setImmediate(() => {
        // The challenge is only solved if query takes > 2000ms (DoS via sleep injection)
        // A fast query should not solve it
        expect(challenges.noSqlCommandChallenge.solved).to.equal(false)
        done()
      })
    })
  })
})
