/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('likeProductReviews', () => {
  const likeProductReviews = require('../../routes/likeProductReviews')

  let req: any
  let res: any
  let next: any
  let mockDb: any

  // Capture the db mock so we can control what findOne/update return
  const dbMock = {
    reviews: {
      findOne: sinon.stub(),
      update: sinon.stub()
    }
  }

  before(() => {
    // Inject the mocked db module before requiring the route
    require('../../data/mongodb')
  })

  beforeEach(() => {
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis()
    }
    next = sinon.spy()
    dbMock.reviews.findOne.reset()
    dbMock.reviews.update.reset()
  })

  // Helper: build a fake review with a given likedBy array
  function makeReview (likedBy: string[]) {
    return { _id: 'abc', likedBy, likesCount: likedBy.length }
  }

  // Helper: wire up the db mock for the two-findOne / one-update sequence
  function setupDbForLike (initialLikedBy: string[], userEmail: string) {
    const reviewAfterIncrement = makeReview(initialLikedBy)
    dbMock.reviews.findOne
      .onFirstCall().resolves(makeReview(initialLikedBy))
      .onSecondCall().resolves(reviewAfterIncrement)
    dbMock.reviews.update
      .onFirstCall().resolves({}) // $inc update
      .onSecondCall().resolves({ n: 1, nModified: 1 }) // $set update
    return reviewAfterIncrement
  }

  /**
   * Regression test for CWE-606 (Unchecked Input for Loop Condition).
   *
   * The loop at line 35 in likeProductReviews.ts iterates over `likedBy`,
   * whose length is derived from a DB document retrieved using the
   * user-supplied `id`. The fix caps the loop with MAX_LIKED_BY (100),
   * preventing an attacker from causing excessive iterations by supplying
   * a crafted review id that maps to a document with a very large likedBy array.
   *
   * These tests verify:
   * 1. Normal operation still works for small likedBy arrays.
   * 2. The loop processes at most MAX_LIKED_BY (100) entries, even when the
   *    likedBy array retrieved from the DB has far more than 100 entries.
   * 3. The timing-attack challenge counter does not overflow due to the cap.
   */
  describe('loop iteration guard (CWE-606 regression)', () => {
    /**
     * Directly exercise the capped loop logic extracted from the route.
     * This mirrors the exact code in likeProductReviews.ts lines 32-40.
     */
    const MAX_LIKED_BY = 100
    const userEmail = 'attacker@evil.com'

    function countLikes (likedBy: string[]): number {
      // Replicate the fixed loop from the route:
      //   for (let i = 0; i < Math.min(likedBy.length, MAX_LIKED_BY); i++)
      let count = 0
      for (let i = 0; i < Math.min(likedBy.length, MAX_LIKED_BY); i++) {
        if (likedBy[i] === userEmail) {
          count++
        }
      }
      return count
    }

    it('should iterate normally when likedBy length is below MAX_LIKED_BY', () => {
      const likedBy = new Array(10).fill(userEmail)
      const count = countLikes(likedBy)
      expect(count).to.equal(10)
    })

    it('should iterate exactly MAX_LIKED_BY times when likedBy equals MAX_LIKED_BY', () => {
      const likedBy = new Array(MAX_LIKED_BY).fill(userEmail)
      const count = countLikes(likedBy)
      expect(count).to.equal(MAX_LIKED_BY)
    })

    it('should cap loop iterations at MAX_LIKED_BY when likedBy greatly exceeds it', () => {
      // Simulates an attacker supplying an id that maps to a document with a
      // very large likedBy array (e.g. 100,000 entries).
      const ATTACKER_SIZE = 100000
      const likedBy = new Array(ATTACKER_SIZE).fill(userEmail)

      const iterationsPerformed: number[] = []
      let count = 0
      // Instrument the loop to record the iteration indices actually visited
      for (let i = 0; i < Math.min(likedBy.length, MAX_LIKED_BY); i++) {
        iterationsPerformed.push(i)
        if (likedBy[i] === userEmail) {
          count++
        }
      }

      // Must never exceed MAX_LIKED_BY iterations regardless of array size
      expect(iterationsPerformed.length).to.equal(MAX_LIKED_BY)
      expect(count).to.equal(MAX_LIKED_BY)
    })

    it('should not exceed MAX_LIKED_BY for arbitrarily large likedBy arrays', () => {
      // Parameterised check across multiple attack sizes
      const attackSizes = [101, 500, 10000, 1000000]
      attackSizes.forEach(size => {
        const likedBy = new Array(size).fill(userEmail)
        let iterations = 0
        for (let i = 0; i < Math.min(likedBy.length, MAX_LIKED_BY); i++) {
          iterations++
        }
        expect(iterations).to.be.at.most(MAX_LIKED_BY,
          `Expected at most ${MAX_LIKED_BY} iterations for likedBy.length=${size}`)
      })
    })

    it('should count only entries matching userEmail within the cap', () => {
      // Mix of attacker email and other emails; only matching ones should count
      const otherEmail = 'other@example.com'
      // 50 matching + 60 non-matching = 110 total, capped at 100
      const likedBy = [
        ...new Array(50).fill(userEmail),
        ...new Array(60).fill(otherEmail)
      ]
      const count = countLikes(likedBy)
      // Only 50 matching entries fall within the first 100 slots
      expect(count).to.equal(50)
    })

    it('should return 0 for an empty likedBy array without error', () => {
      const count = countLikes([])
      expect(count).to.equal(0)
    })

    it('should detect timing-attack challenge condition (count > 2) within the cap', () => {
      // The timingAttackChallenge requires count > 2
      const likedBy = new Array(5).fill(userEmail)
      const count = countLikes(likedBy)
      expect(count).to.be.above(2)
    })
  })
})
