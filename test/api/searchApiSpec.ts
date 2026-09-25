/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
import { type Product } from '../../data/types'
import config from 'config'

const christmasProduct = config.get<Product[]>('products').filter(({ useForChristmasSpecialChallenge }: Product) => useForChristmasSpecialChallenge)[0]
const pastebinLeakProduct = config.get<Product[]>('products').filter(({ keywordsForPastebinDataLeakChallenge }: Product) => keywordsForPastebinDataLeakChallenge)[0]

const API_URL = 'http://localhost:3000/api'
const REST_URL = 'http://localhost:3000/rest'

describe('/rest/products/search', () => {
  it('GET product search with no matches returns no products', () => {
    return frisby.get(`${REST_URL}/products/search?q=nomatcheswhatsoever`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with one match returns found product', () => {
    return frisby.get(`${REST_URL}/products/search?q=o-saft`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(1)
      })
  })

  // SQL injection payloads must now be treated as literal search strings (parameterized queries)
  it('GET product search with SQL injection payload returns 200 with no results instead of SQL error', () => {
    return frisby.get(`${REST_URL}/products/search?q=';`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // The payload is treated as a literal search string, not executed as SQL
        expect(json.data).toBeDefined()
        expect(Array.isArray(json.data)).toBe(true)
      })
  })

  it('GET product search SQL Injection UNION SELECT payload returns 200 with no injected data', () => {
    return frisby.get(`${REST_URL}/products/search?q=' union select id,email,password from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Parameterized query treats the payload as a literal LIKE pattern, finds no matching products
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search SQL Injection with closing parentheses returns 200 with no injected data', () => {
    return frisby.get(`${REST_URL}/products/search?q=') union select id,email,password from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Parameterized query treats the payload as a literal LIKE pattern, finds no matching products
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search SQL Injection with double closing parentheses returns 200 with no injected data', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select * from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Parameterized query treats the payload as a literal LIKE pattern, finds no matching products
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search SQL Injection UNION with fixed columns returns no injected user data', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select '1','2','3','4','5','6','7','8','9' from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // No injected rows with fabricated column values should appear
        const fabricatedRows = json.data.filter((item: any) => item.id === '1' && item.name === '2')
        expect(fabricatedRows.length).toBe(0)
      })
  })

  it('GET product search SQL Injection with user credentials payload returns no user data', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select id,'2','3',email,password,'6','7','8','9' from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // No rows with actual user email/password data should be returned
        const usersLeaked = json.data.filter((item: any) =>
          typeof item.price === 'string' && item.price.includes('@')
        )
        expect(usersLeaked.length).toBe(0)
      })
  })

  it('GET product search SQL Injection against sqlite_master returns no schema data', () => {
    return frisby.get(`${REST_URL}/products/search?q=')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // No rows containing CREATE TABLE statements should be returned
        const schemaLeaked = json.data.filter((item: any) =>
          typeof item.id === 'string' && item.id.startsWith('CREATE TABLE')
        )
        expect(schemaLeaked.length).toBe(0)
      })
  })

  it('GET product search cannot select logically deleted christmas special by default', () => {
    return frisby.get(`${REST_URL}/products/search?q=seasonal%20special%20offer`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search by description cannot select logically deleted christmas special via SQL comment injection', () => {
    return frisby.get(`${REST_URL}/products/search?q=seasonal%20special%20offer'))--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // SQL comment injection attempt is treated as literal search criteria
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search cannot bypass deletedAt filter via SQL comment injection', () => {
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent(christmasProduct.name + "'))--")}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // With parameterized queries the comment injection does not bypass the WHERE clause
        // The product remains hidden because deletedAt IS NULL filter cannot be removed
        const deletedProductReturned = json.data.filter((item: any) => item.name === christmasProduct.name)
        expect(deletedProductReturned.length).toBe(0)
      })
  })

  it('GET product search cannot bypass deletedAt filter for unsafe product via SQL comment injection', () => {
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent(pastebinLeakProduct.name + "'))--")}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // With parameterized queries the comment injection does not bypass the WHERE clause
        const deletedProductReturned = json.data.filter((item: any) => item.name === pastebinLeakProduct.name)
        expect(deletedProductReturned.length).toBe(0)
      })
  })

  it('GET product search with empty search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search?q=`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })

  it('GET product search without search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })

  it('GET product search with special characters returns 200 and treats them as literal search terms', () => {
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent("'; DROP TABLE Products; --")}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Destructive SQL payload is treated as a literal string, no error and no table dropped
        expect(Array.isArray(json.data)).toBe(true)
      })
  })

  it('GET product search with percent sign returns 200 without SQL errors', () => {
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent('%')}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(Array.isArray(json.data)).toBe(true)
      })
  })
})
