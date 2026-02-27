const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server')
const Database = require('../Database')
const Logger = require('../Logger')

const challenges = new Map()

class WebAuthnController {
  constructor() {
    this.rpName = 'Audiobookshelf'
  }

  getRpId(req) {
    return req.hostname
  }

  getExpectedOrigin(req) {
    return `${req.protocol}://${req.get('host')}`
  }

  async generateRegisterOptions(req, res) {
    try {
      const user = req.user
      if (!user) return res.status(401).json({ error: 'Unauthorized' })

      const rpID = this.getRpId(req)

      const existingKeys = await Database.userPasskeyModel.findAll({ where: { userId: user.id } })
      const excludeCredentials = existingKeys.map((key) => ({
        id: Buffer.from(key.credentialID, 'base64url'),
        type: 'public-key',
        transports: key.transports ? JSON.parse(key.transports) : []
      }))

      const options = await generateRegistrationOptions({
        rpName: this.rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        authenticatorSelection: {
          userVerification: 'preferred',
          residentKey: 'required'
        },
        excludeCredentials
      })

      challenges.set(`reg_${user.id}`, options.challenge)
      res.json(options)
    } catch (error) {
      Logger.error(`[WebAuthn] Generate Register Options failed:`, error)
      res.status(500).json({ error: 'Internal Server Error' })
    }
  }

  async verifyRegisterResponse(req, res) {
    try {
      const user = req.user
      if (!user) return res.status(401).json({ error: 'Unauthorized' })

      const expectedChallenge = challenges.get(`reg_${user.id}`)
      if (!expectedChallenge) return res.status(400).json({ error: 'No active registration challenge found' })

      const body = req.body
      let verification

      try {
        verification = await verifyRegistrationResponse({
          response: body,
          expectedChallenge,
          expectedOrigin: this.getExpectedOrigin(req),
          expectedRPID: this.getRpId(req)
        })
      } catch (error) {
        Logger.error(`[WebAuthn] Verification failed:`, error)
        return res.status(400).json({ error: error.message })
      }

      const { verified, registrationInfo } = verification

      if (verified && registrationInfo) {
        const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo

        await Database.userPasskeyModel.create({
          userId: user.id,
          credentialID: credential.id,
          credentialPublicKey: credential.publicKey,
          counter: credential.counter,
          transports: JSON.stringify(credential.transports || []),
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp
        })

        challenges.delete(`reg_${user.id}`)
        res.json({ success: true })
      } else {
        res.status(400).json({ error: 'Verification failed' })
      }
    } catch (error) {
      Logger.error(`[WebAuthn] Verify Register Response failed:`, error)
      res.status(500).json({ error: 'Internal Server Error' })
    }
  }

  async generateLoginOptions(req, res) {
    try {
      const options = await generateAuthenticationOptions({
        rpID: this.getRpId(req),
        userVerification: 'preferred'
      })

      const identifier = req.ip
      challenges.set(`login_${identifier}`, options.challenge)

      res.json(options)
    } catch (error) {
      Logger.error(`[WebAuthn] Generate Login Options failed:`, error)
      res.status(500).json({ error: 'Internal Server Error' })
    }
  }

  async verifyLoginResponse(req, res, next) {
    try {
      const body = req.body
      const identifier = req.ip
      const expectedChallenge = challenges.get(`login_${identifier}`)

      if (!expectedChallenge) return res.status(400).json({ error: 'No active login challenge found' })

      const passkey = await Database.userPasskeyModel.findOne({ where: { credentialID: body.id } })
      if (!passkey) return res.status(400).json({ error: 'Passkey not found' })

      const user = await Database.userModel.findByPk(passkey.userId)
      if (!user) return res.status(400).json({ error: 'User not found' })

      let verification
      try {
        verification = await verifyAuthenticationResponse({
          response: body,
          expectedChallenge,
          expectedOrigin: this.getExpectedOrigin(req),
          expectedRPID: this.getRpId(req),
          credential: {
            id: passkey.credentialID,
            publicKey: passkey.credentialPublicKey,
            counter: passkey.counter,
            transports: passkey.transports ? JSON.parse(passkey.transports) : []
          }
        })
      } catch (error) {
        Logger.error(`[WebAuthn] Authentication verification failed:`, error)
        return res.status(400).json({ error: error.message })
      }

      if (verification.verified) {
        passkey.counter = verification.authenticationInfo.newCounter
        await passkey.save()
        challenges.delete(`login_${identifier}`)

        req.user = user
        req.isPasskeyLogin = true
        next()
      } else {
        res.status(400).json({ error: 'Authentication failed' })
      }
    } catch (error) {
      Logger.error(`[WebAuthn] Verify Login Response failed:`, error)
      res.status(500).json({ error: 'Internal Server Error' })
    }
  }
}

module.exports = new WebAuthnController()
