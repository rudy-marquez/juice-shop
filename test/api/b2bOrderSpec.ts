/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
const Joi = frisby.Joi
const utils = require('../../lib/utils')
const security = require('../../lib/insecurity')

const API_URL = 'http://localhost:3000/b2b/v2/orders'

const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

describe('/b2b/v2/orders', () => {
  if (!utils.disableOnContainerEnv()) {
    it('POST code execution payload in "orderLinesData" is rejected as invalid JSON', () => {
      return frisby.post(API_URL, {
        headers: authHeader,
        body: {
          orderLinesData: '(function dos() { while(true); })()'
        }
      })
        .expect('status', 500)
    })

    it('POST ReDoS regex payload in "orderLinesData" is rejected as invalid JSON', () => {
      return frisby.post(API_URL, {
        headers: authHeader,
        body: {
          orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
        }
      })
        .expect('status', 500)
    })

    it('POST sandbox breakout attack in "orderLinesData" is rejected as invalid JSON', () => {
      return frisby.post(API_URL, {
        headers: authHeader,
        body: {
          orderLinesData: 'this.constructor.constructor("return process")().exit()'
        }
      })
        .expect('status', 500)
    })
  }

  it('POST new B2B order is forbidden without authorization token', () => {
    return frisby.post(API_URL, {})
      .expect('status', 401)
  })

  it('POST new B2B order accepts arbitrary valid JSON', () => {
    return frisby.post(API_URL, {
      headers: authHeader,
      body: {
        foo: 'bar',
        test: 42
      }
    })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', {
        cid: Joi.string(),
        orderNo: Joi.string(),
        paymentDue: Joi.string()
      })
  })

  it('POST new B2B order has passed "cid" in response', () => {
    return frisby.post(API_URL, {
      headers: authHeader,
      body: {
        cid: 'test'
      }
    })
      .expect('status', 200)
      .expect('json', {
        cid: 'test'
      })
  })

  it('POST valid JSON orderLinesData returns successful order', () => {
    return frisby.post(API_URL, {
      headers: authHeader,
      body: {
        cid: 'customer-123',
        orderLinesData: '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2"]}'
      }
    })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', {
        cid: Joi.string(),
        orderNo: Joi.string(),
        paymentDue: Joi.string()
      })
  })

  it('POST malformed JSON in orderLinesData returns error', () => {
    return frisby.post(API_URL, {
      headers: authHeader,
      body: {
        orderLinesData: '{ "productId: 28'
      }
    })
      .expect('status', 500)
  })
})
