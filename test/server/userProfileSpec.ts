/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

// Minimal pug template that mirrors the relevant part of views/userProfile.pug.
// Using a plain string replacement placeholder so pug.compile does not fail
// in a unit-test environment that has no real theme/config data.
const MINIMAL_PUG_TEMPLATE = 'p _username_'

describe('userProfile', () => {
  // Route factory
  let getUserProfile: () => (req: any, res: any, next: any) => void

  // Express-like stubs
  let req: any
  let res: any
  let next: sinon.SinonSpy

  // Dependency stubs
  let fsStub: sinon.SinonStub
  let findByPkStub: sinon.SinonStub
  let securityStub: any

  beforeEach(() => {
    // Stub fs.readFile to return our minimal template synchronously
    const fs = require('fs')
    fsStub = sinon.stub(fs, 'readFile').callsFake((_path: string, cb: Function) => {
      cb(null, Buffer.from(MINIMAL_PUG_TEMPLATE))
    })

    // Stub UserModel.findByPk
    const userModel = require('../../models/user')
    findByPkStub = sinon.stub(userModel.UserModel, 'findByPk')

    // Stub security module so token lookup always returns a logged-in user
    securityStub = require('../../lib/insecurity')
    sinon.stub(securityStub.authenticatedUsers, 'get').returns({
      data: { id: 1, email: 'test@example.com' }
    })

    // Build a minimal req / res / next
    req = {
      cookies: { token: 'test-token' },
      app: { locals: {} }
    }
    res = {
      set: sinon.spy(),
      send: sinon.spy()
    }
    next = sinon.spy()

    // Re-require the route AFTER stubs are in place so it picks up stubbed modules
    delete require.cache[require.resolve('../../routes/userProfile')]
    getUserProfile = require('../../routes/userProfile')
  })

  afterEach(() => {
    sinon.restore()
    // Clear the route cache so stubs are fresh for the next test
    delete require.cache[require.resolve('../../routes/userProfile')]
  })

  /**
   * Helper: build a mock UserModel instance returned by findByPk.
   */
  function mockUser (username: string | undefined) {
    return {
      id: 1,
      username,
      email: 'test@example.com',
      profileImage: '/assets/public/images/uploads/default.svg'
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Stored Code Injection (CWE-94) prevention
  // ──────────────────────────────────────────────────────────────────────────

  it('should NOT execute JavaScript embedded in a Pug SSTI username payload', (done) => {
    // Arrange: username crafted to exploit the old eval() sink
    const maliciousUsername = '#{"pwned" + (1+1)}'
    findByPkStub.resolves(mockUser(maliciousUsername))

    // Spy on eval to assert it is never called — if it were, the injection succeeded
    const evalSpy = sinon.spy(global, 'eval' as any)

    getUserProfile()(req, res, next)

    setImmediate(() => {
      // eval must never be called with the extracted payload
      expect(evalSpy.called).to.equal(false)
      // The response must have been sent (route completed normally)
      expect(res.send).to.have.been.calledOnce
      // The abused_ssti_bug flag must be set so the detection still works
      expect(req.app.locals.abused_ssti_bug).to.equal(true)

      evalSpy.restore()
      done()
    })
  })

  it('should NOT evaluate arithmetic in a SSTI-pattern username', (done) => {
    // A payload that, if eval'd, would produce a number instead of the literal string
    const arithmeticPayload = '#{ 1 + 1 }'
    findByPkStub.resolves(mockUser(arithmeticPayload))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(res.send).to.have.been.calledOnce
      // The page should contain the escaped literal username, not the evaluated result '2'
      const renderedHtml: string = res.send.firstCall.args[0]
      expect(renderedHtml).to.not.include('2') // eval would have produced '2'
      done()
    })
  })

  it('should NOT execute code that sets a global side-effect via SSTI payload', (done) => {
    // If eval() ran this payload it would set a global variable
    ;(global as any).__ssti_injection_marker = false
    const sideEffectPayload = '#{ (function(){ (global || globalThis).__ssti_injection_marker = true; return ""; })() }'
    findByPkStub.resolves(mockUser(sideEffectPayload))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect((global as any).__ssti_injection_marker).to.equal(false)
      expect(res.send).to.have.been.calledOnce
      delete (global as any).__ssti_injection_marker
      done()
    })
  })

  it('should mark abused_ssti_bug flag when username contains SSTI pattern', (done) => {
    const sstiUsername = '#{process.version}'
    findByPkStub.resolves(mockUser(sstiUsername))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(req.app.locals.abused_ssti_bug).to.equal(true)
      done()
    })
  })

  it('should NOT mark abused_ssti_bug flag for a normal username', (done) => {
    findByPkStub.resolves(mockUser('JaneDoe'))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      // Flag must remain falsy (undefined) for an innocent username
      expect(req.app.locals.abused_ssti_bug).to.not.equal(true)
      done()
    })
  })

  // ──────────────────────────────────────────────────────────────────────────
  // Normal profile rendering
  // ──────────────────────────────────────────────────────────────────────────

  it('should render the profile page for a normal username', (done) => {
    findByPkStub.resolves(mockUser('Localhorst'))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(res.send).to.have.been.calledOnce
      done()
    })
  })

  it('should render the profile page for a user with an undefined username', (done) => {
    findByPkStub.resolves(mockUser(undefined))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(res.send).to.have.been.calledOnce
      done()
    })
  })

  it('should set Content-Security-Policy header on a successful profile request', (done) => {
    findByPkStub.resolves(mockUser('TestUser'))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(res.set).to.have.been.called
      done()
    })
  })

  // ──────────────────────────────────────────────────────────────────────────
  // Authentication gate
  // ──────────────────────────────────────────────────────────────────────────

  it('should call next with an error when no logged-in user is present', (done) => {
    // Override the stub so no user is found for the token
    securityStub.authenticatedUsers.get.restore()
    sinon.stub(securityStub.authenticatedUsers, 'get').returns(null)

    req.socket = { remoteAddress: '127.0.0.1' }
    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(Error)
      expect(next.firstCall.args[0].message).to.include('Blocked illegal activity')
      done()
    })
  })

  it('should propagate database errors via next()', (done) => {
    findByPkStub.rejects(new Error('DB connection failed'))

    getUserProfile()(req, res, next)

    setImmediate(() => {
      expect(next).to.have.been.calledOnce
      expect(next.firstCall.args[0]).to.be.instanceOf(Error)
      done()
    })
  })
})
