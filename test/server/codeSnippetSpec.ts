import sinon = require('sinon')
import chai = require('chai')
import path from 'path'
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)
const { getVerdict } = require('../../routes/vulnCodeSnippet')
const vulnCodeSnippet = require('../../routes/vulnCodeSnippet')

describe('vulnCodeSnippet', () => {
  it('should assert single correctly selected vuln line as correct', () => {
    expect(getVerdict([1], [], [1])).to.equal(true)
  })

  it('should assert multiple correctly selected vuln lines as correct in any order', () => {
    expect(getVerdict([1, 2], [], [1, 2])).to.equal(true)
    expect(getVerdict([1, 2], [], [2, 1])).to.equal(true)
    expect(getVerdict([1, 2, 3], [], [3, 1, 2])).to.equal(true)
  })

  it('should ignore selected neutral lines during correct assertion', () => {
    expect(getVerdict([1, 2], [3, 4], [1, 2, 3])).to.equal(true)
    expect(getVerdict([1, 2], [3, 4], [1, 2, 4])).to.equal(true)
    expect(getVerdict([1, 2], [3, 4], [1, 2, 3, 4])).to.equal(true)
  })

  it('should assert missing vuln lines as wrong', () => {
    expect(getVerdict([1, 2], [], [1])).to.equal(false)
    expect(getVerdict([1, 2], [], [2])).to.equal(false)
    expect(getVerdict([1, 2], [3], [2, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3], [1, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3, 4], [3, 4])).to.equal(false)
  })

  it('should assert additionally selected lines as wrong', () => {
    expect(getVerdict([1, 2], [], [1, 2, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3], [1, 2, 3, 4])).to.equal(false)
  })

  it('should assert lack of selected lines as wrong', () => {
    expect(getVerdict([1, 2], [], [])).to.equal(false)
  })

  it('should assert empty edge case as correct', () => {
    expect(getVerdict([], [], [])).to.equal(true)
  })
})

describe('checkVulnLines path traversal prevention', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = {
      status: sinon.stub().returnsThis(),
      json: sinon.spy()
    }
    next = sinon.spy()
  })

  it('should reject a key with ../ path traversal sequence', async () => {
    req = {
      body: {
        key: '../../../etc/passwd',
        selectedLines: [1]
      }
    }
    await vulnCodeSnippet.checkVulnLines()(req, res, next)
    expect(res.status).to.have.been.calledWith(sinon.match((v: number) => v === 400 || v === 404))
  })

  it('should reject a key with absolute path traversal starting with /', async () => {
    req = {
      body: {
        key: '/etc/passwd',
        selectedLines: [1]
      }
    }
    await vulnCodeSnippet.checkVulnLines()(req, res, next)
    // Key '/etc/passwd' resolves outside codefixes base directory — must be rejected
    const statusCall = res.status.args[0]
    expect(statusCall[0]).to.be.oneOf([400, 404])
  })

  it('should reject a key with encoded path traversal sequence', async () => {
    req = {
      body: {
        key: '..%2F..%2Fetc%2Fpasswd',
        selectedLines: [1]
      }
    }
    await vulnCodeSnippet.checkVulnLines()(req, res, next)
    const statusCall = res.status.args[0]
    expect(statusCall[0]).to.be.oneOf([400, 404])
  })

  it('should reject a key attempting to escape the codefixes directory with backslash traversal', async () => {
    req = {
      body: {
        key: '..\\..\\etc\\passwd',
        selectedLines: [1]
      }
    }
    await vulnCodeSnippet.checkVulnLines()(req, res, next)
    const statusCall = res.status.args[0]
    expect(statusCall[0]).to.be.oneOf([400, 404])
  })

  it('should reject a key with a nested traversal bypassing naive prefix check', async () => {
    // e.g. "data/static/codefixes/../../../etc/passwd"
    req = {
      body: {
        key: 'loginAdminChallenge/../../../../../../etc/passwd',
        selectedLines: [1]
      }
    }
    await vulnCodeSnippet.checkVulnLines()(req, res, next)
    const statusCall = res.status.args[0]
    expect(statusCall[0]).to.be.oneOf([400, 404])
  })

  it('should verify that path.resolve containment check blocks traversal', () => {
    // Unit-level check: confirm that path.resolve properly resolves traversal payloads
    const baseDir = path.resolve('./data/static/codefixes')
    const traversalKey = '../../../etc/passwd'
    const resolvedPath = path.resolve(baseDir, traversalKey + '.info.yml')
    expect(resolvedPath.startsWith(baseDir + path.sep)).to.equal(false)
  })

  it('should verify that a legitimate challenge key passes the containment check', () => {
    const baseDir = path.resolve('./data/static/codefixes')
    const legitimateKey = 'loginAdminChallenge'
    const resolvedPath = path.resolve(baseDir, legitimateKey + '.info.yml')
    expect(resolvedPath.startsWith(baseDir + path.sep)).to.equal(true)
  })

  it('should verify that a key with leading slash is blocked by containment check', () => {
    const baseDir = path.resolve('./data/static/codefixes')
    const absoluteKey = '/etc/passwd'
    const resolvedPath = path.resolve(baseDir, absoluteKey + '.info.yml')
    expect(resolvedPath.startsWith(baseDir + path.sep)).to.equal(false)
  })
})
