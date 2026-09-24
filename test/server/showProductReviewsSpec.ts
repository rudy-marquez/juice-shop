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
  const showProductReviews = require('../../routes/showProductReviews')
  const challenges = require('../../data/datacache').challenges
  let req: any
  let res: any
  let mongoDB: any
  let findStub: sinon.SinonStub

  beforeEach(() => {
    req = { params: {}, headers: {} }
    res = { json: sinon.spy(), status: sinon.stub().returns({ json: sinon.spy() }) }

    mongoDB = require('../../data/mongodb')
    findStub = sinon.stub(mongoDB.reviews, 'find')
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('NoSQL injection prevention', () => {
    it('should use plain field equality query, not a $where string-interpolation expression', () => {
      // The old vulnerable code was: { $where: 'this.product == ' + id }
      // The safe code must be:       { product: id }
      const productId = '1'
      findStub.returns(Promise.resolve([]))
      req.params.id = productId

      showProductReviews()(req, res)

      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      // Must NOT use the dangerous $where operator
      expect(queryArg).to.not.have.property('$where')
      // Must use safe field equality
      expect(queryArg).to.have.property('product')
    })

    it('should treat a JavaScript injection payload as a literal field value, not executable code', () => {
      // Classic $where injection: "this.product == 1; return true //" would return all documents.
      // With the safe query { product: id } the payload becomes a literal string — no injection.
      const injectionPayload = '1; return true //'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      showProductReviews()(req, res)

      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })

    it('should not allow always-true injection payload to match every review', () => {
      // "this.product == 1 || 1==1" would have matched ALL reviews with $where.
      const injectionPayload = '1 || 1==1'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      showProductReviews()(req, res)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      // The payload is used verbatim as the field value — safe
      expect(queryArg).to.have.property('product')
    })

    it('should not allow while(1) DoS payload to be executed via $where', () => {
      // "this.product == 1 || while(1){}" would cause an infinite loop with $where.
      const injectionPayload = '1 || while(1){}'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      showProductReviews()(req, res)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })

    it('should not allow sleep-based DoS payload to be executed via $where', () => {
      // "this.product == 1; sleep(2000)" would have caused a timed delay with $where.
      const injectionPayload = '1; sleep(2000)'
      findStub.returns(Promise.resolve([]))
      req.params.id = injectionPayload

      showProductReviews()(req, res)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })
  })

  describe('normal product reviews retrieval', () => {
    it('should query reviews using the product id as a plain equality filter', (done) => {
      const productId = '42'
      const mockReviews = [{ product: 42, message: 'Great product', likedBy: [] }]
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = productId

      showProductReviews()(req, res)

      setImmediate(() => {
        expect(findStub).to.have.been.calledOnce
        const queryArg = findStub.firstCall.args[0]
        expect(queryArg).to.not.have.property('$where')
        expect(queryArg).to.have.property('product')
        done()
      })
    })

    it('should return reviews as JSON when the database query succeeds', (done) => {
      const mockReviews = [{ product: 1, message: 'Awesome', likedBy: [] }]
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = '1'

      showProductReviews()(req, res)

      setImmediate(() => {
        expect(res.json).to.have.been.called
        done()
      })
    })

    it('should return a 400 error when the database query fails', (done) => {
      findStub.returns(Promise.reject(new Error('DB error')))
      req.params.id = '1'

      showProductReviews()(req, res)

      setImmediate(() => {
        expect(res.status).to.have.been.calledWith(400)
        done()
      })
    })

    it('should return an empty list when no reviews exist for the product', (done) => {
      findStub.returns(Promise.resolve([]))
      req.params.id = '999'

      showProductReviews()(req, res)

      setImmediate(() => {
        expect(res.json).to.have.been.called
        done()
      })
    })
  })
})
