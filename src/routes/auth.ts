import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { OAuth2Client } from 'google-auth-library'
import nodemailer from 'nodemailer'
import type { JwtPayload } from '../lib/authenticate.js'
import { authenticate } from '../lib/authenticate.js'

// ── Constants ─────────────────────────────────────────────────────────────────

const ACCESS_TTL_S  = 15 * 60         // 15 minutes
const REFRESH_TTL_S = 7 * 24 * 3600   // 7 days
const OTP_TTL_S     = 600             // 10 minutes
const MAGIC_TTL_S   = 900             // 15 minutes

// ── Helpers ───────────────────────────────────────────────────────────────────

function issueTokens(userId: string, role: string): { access_token: string; refresh_token: string } {
  const payload: JwtPayload = { userId, role }
  const access_token  = jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: ACCESS_TTL_S })
  const refresh_token = jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, { expiresIn: REFRESH_TTL_S })
  return { access_token, refresh_token }
}

function randomOtp(): string {
  return String(Math.floor(100000 + Math.random() * 900000))
}

function getMailer() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST ?? 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  })
}

async function sendOtpEmail(email: string, otp: string) {
  if (process.env.EMAIL_DEV_MODE === 'true' || !process.env.SMTP_USER) {
    console.log(`[DEV] Email OTP for ${email}: ${otp}`)
    return
  }
  const mailer = getMailer()
  await mailer.sendMail({
    from: process.env.SMTP_FROM ?? process.env.SMTP_USER,
    to: email,
    subject: 'BharatTruck — Verify your email',
    text: `Your BharatTruck verification code is: ${otp}\n\nExpires in 10 minutes.`,
    html: `<p>Your BharatTruck verification code is: <strong>${otp}</strong></p><p>Expires in 10 minutes.</p>`,
  })
}

async function sendMagicLinkEmail(email: string, link: string) {
  if (process.env.EMAIL_DEV_MODE === 'true' || !process.env.SMTP_USER) {
    console.log(`[DEV] Magic link for ${email}: ${link}`)
    return
  }
  const mailer = getMailer()
  await mailer.sendMail({
    from: process.env.SMTP_FROM ?? process.env.SMTP_USER,
    to: email,
    subject: 'BharatTruck — Sign in link',
    text: `Sign in to BharatTruck: ${link}\n\nExpires in 15 minutes.`,
    html: `<p>Click to sign in to BharatTruck: <a href="${link}">${link}</a></p><p>Expires in 15 minutes.</p>`,
  })
}

// Returns the public user shape both apps expect
function userProfile(row: Record<string, unknown>) {
  return {
    id:             row.id,
    phone:          row.phone_number ?? null,
    email:          row.email ?? null,
    full_name:      row.full_name ?? null,
    avatar_url:     row.avatar_url ?? null,
    role:           row.role,
    email_verified: row.email_verified ?? false,
    google_sub:     row.google_sub ?? null,
    created_at:     row.created_at,
  }
}

// ── Schemas ───────────────────────────────────────────────────────────────────

const PhoneOtpBody       = z.object({ phone: z.string().regex(/^[6-9]\d{9}$/, 'Invalid Indian phone number') })
const VerifyOtpBody      = z.object({ phone: z.string(), otp: z.string().length(6) })
const EmailRegisterBody  = z.object({
  email:     z.string().email(),
  password:  z.string().min(8),
  full_name: z.string().min(2).max(100),
  role:      z.enum(['shipper', 'driver', 'fleet_owner']).default('shipper'),
})
const EmailVerifyBody    = z.object({ email: z.string().email(), otp: z.string().length(6) })
const EmailLoginBody     = z.object({ email: z.string().email(), password: z.string() })
const ResendOtpBody      = z.object({ email: z.string().email() })
const MagicLinkSendBody  = z.object({
  email:        z.string().email(),
  role:         z.string().optional(),
  callback_url: z.string().url().optional(),
})
const GoogleSignInBody   = z.object({ id_token: z.string(), role: z.enum(['shipper', 'driver', 'fleet_owner']).default('shipper') })
const RefreshBody        = z.object({ refresh_token: z.string() })
const RegisterProfileBody = z.object({
  full_name:    z.string().min(2).max(100),
  role:         z.enum(['shipper', 'driver', 'fleet_owner']),
  email:        z.string().email().optional(),
  truck_type:   z.string().optional(),
  truck_number: z.string().optional(),
  license_number: z.string().optional(),
})

// ── Route plugin ──────────────────────────────────────────────────────────────

export async function authRoutes(app: FastifyInstance) {

  // ── POST /auth/send-otp ──────────────────────────────────────────────────────

  app.post('/send-otp', async (req, reply) => {
    const body = PhoneOtpBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { phone } = body.data

    const rateKey = `otp_rate:${phone}`
    const attempts = await app.redis.incr(rateKey)
    if (attempts === 1) await app.redis.expire(rateKey, 3600)
    if (attempts > 5) {
      return reply.status(429).send({ success: false, error: 'Too many OTP requests. Try again in 1 hour.' })
    }

    const otp = randomOtp()
    await app.redis.set(`phone_otp:${phone}`, otp, 'EX', OTP_TTL_S)

    if (process.env.OTP_DEV_MODE === 'true' || process.env.NODE_ENV === 'development') {
      console.log(`[DEV] Phone OTP for +91${phone}: ${otp}`)
    } else {
      // Production: integrate Twilio or MSG91 here
      // await sendSms(phone, otp)
      console.log(`[WARN] No SMS provider configured — OTP for ${phone}: ${otp}`)
    }

    return reply.send({ success: true, data: { message: 'OTP sent', expires_in: OTP_TTL_S } })
  })

  // ── POST /auth/verify-otp ────────────────────────────────────────────────────

  app.post('/verify-otp', async (req, reply) => {
    const body = VerifyOtpBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { phone, otp } = body.data

    const stored = await app.redis.get(`phone_otp:${phone}`)
    if (!stored || stored !== otp) {
      return reply.status(401).send({ success: false, error: 'Invalid or expired OTP' })
    }
    await app.redis.del(`phone_otp:${phone}`)

    // Upsert user by phone
    let { data: user } = await app.supabase
      .from('users')
      .select('*')
      .eq('phone_number', phone)
      .maybeSingle()

    const is_new_user = !user
    if (!user) {
      const { data: newUser, error } = await app.supabase
        .from('users')
        .insert({ phone_number: phone, role: 'shipper' })
        .select('*')
        .single()
      if (error || !newUser) {
        return reply.status(500).send({ success: false, error: 'Failed to create user' })
      }
      user = newUser
    }

    const { access_token, refresh_token } = issueTokens(user.id, user.role)
    await app.redis.set(`refresh:${user.id}`, refresh_token, 'EX', REFRESH_TTL_S)

    return reply.send({
      success: true,
      data: {
        access_token,
        refresh_token,
        is_new_user,
        user: userProfile(user),
      },
    })
  })

  // ── POST /auth/email/register ────────────────────────────────────────────────

  app.post('/email/register', async (req, reply) => {
    const body = EmailRegisterBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { email, password, full_name, role } = body.data

    const { data: existing } = await app.supabase
      .from('users')
      .select('id, email_verified')
      .eq('email', email)
      .maybeSingle()

    if (existing) {
      if (!existing.email_verified) {
        // Resend OTP so the user can complete verification
        const otp = randomOtp()
        await app.redis.set(`email_otp:${email}`, otp, 'EX', OTP_TTL_S)
        await sendOtpEmail(email, otp)
        return reply.status(409).send({
          success: false,
          error: 'Email already registered but not verified. A new OTP has been sent.',
          code: 'EMAIL_NOT_VERIFIED',
        })
      }
      return reply.status(409).send({ success: false, error: 'Email already registered', code: 'EMAIL_EXISTS' })
    }

    const password_hash = await bcrypt.hash(password, 12)
    const { data: user, error } = await app.supabase
      .from('users')
      .insert({ email, password_hash, full_name, role, email_verified: false })
      .select('*')
      .single()
    if (error || !user) {
      return reply.status(500).send({ success: false, error: 'Failed to create account' })
    }

    const otp = randomOtp()
    await app.redis.set(`email_otp:${email}`, otp, 'EX', OTP_TTL_S)
    await sendOtpEmail(email, otp)

    return reply.status(201).send({
      success: true,
      data: {
        message:        'Account created. Check your email for the verification code.',
        email_verified: false,
        user_id:        user.id,
        expires_in:     OTP_TTL_S,
      },
    })
  })

  // ── POST /auth/email/verify ──────────────────────────────────────────────────

  app.post('/email/verify', async (req, reply) => {
    const body = EmailVerifyBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { email, otp } = body.data

    const stored = await app.redis.get(`email_otp:${email}`)
    if (!stored || stored !== otp) {
      return reply.status(401).send({ success: false, error: 'Invalid or expired verification code' })
    }
    await app.redis.del(`email_otp:${email}`)

    const { data: user, error } = await app.supabase
      .from('users')
      .update({ email_verified: true })
      .eq('email', email)
      .select('*')
      .single()
    if (error || !user) {
      return reply.status(404).send({ success: false, error: 'User not found' })
    }

    // Create driver row if role is driver
    if (user.role === 'driver') {
      await app.supabase.from('drivers').upsert({ user_id: user.id }, { onConflict: 'user_id' })
    }

    const { access_token, refresh_token } = issueTokens(user.id, user.role)
    await app.redis.set(`refresh:${user.id}`, refresh_token, 'EX', REFRESH_TTL_S)

    return reply.send({
      success: true,
      data: {
        access_token,
        refresh_token,
        is_new_user: true,
        user: userProfile(user),
      },
    })
  })

  // ── POST /auth/email/login ───────────────────────────────────────────────────

  app.post('/email/login', async (req, reply) => {
    const body = EmailLoginBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { email, password } = body.data

    const { data: user } = await app.supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle()

    if (!user || !user.password_hash) {
      return reply.status(401).send({ success: false, error: 'Invalid email or password' })
    }

    const match = await bcrypt.compare(password, user.password_hash)
    if (!match) {
      return reply.status(401).send({ success: false, error: 'Invalid email or password' })
    }

    if (!user.email_verified) {
      // Issue a fresh OTP so they can verify
      const otp = randomOtp()
      await app.redis.set(`email_otp:${email}`, otp, 'EX', OTP_TTL_S)
      await sendOtpEmail(email, otp)
      return reply.status(403).send({
        success: false,
        error: 'Email not verified. A verification code has been sent to your email.',
        code: 'EMAIL_NOT_VERIFIED',
      })
    }

    const { access_token, refresh_token } = issueTokens(user.id, user.role)
    await app.redis.set(`refresh:${user.id}`, refresh_token, 'EX', REFRESH_TTL_S)

    return reply.send({
      success: true,
      data: {
        access_token,
        refresh_token,
        is_new_user: false,
        user: userProfile(user),
      },
    })
  })

  // ── POST /auth/email/resend-otp ──────────────────────────────────────────────

  app.post('/email/resend-otp', async (req, reply) => {
    const body = ResendOtpBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { email } = body.data

    const { data: user } = await app.supabase
      .from('users')
      .select('id, email_verified')
      .eq('email', email)
      .maybeSingle()

    if (!user) {
      // Respond with success regardless to avoid email enumeration
      return reply.send({ success: true, data: { message: 'If that email is registered, a code was sent.', expires_in: OTP_TTL_S } })
    }

    if (user.email_verified) {
      return reply.status(400).send({ success: false, error: 'Email is already verified' })
    }

    const otp = randomOtp()
    await app.redis.set(`email_otp:${email}`, otp, 'EX', OTP_TTL_S)
    await sendOtpEmail(email, otp)

    return reply.send({ success: true, data: { message: 'Verification code sent', expires_in: OTP_TTL_S } })
  })

  // ── POST /auth/magic-link/send ───────────────────────────────────────────────

  app.post('/magic-link/send', async (req, reply) => {
    const body = MagicLinkSendBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { email, role, callback_url } = body.data

    // Upsert: create account if doesn't exist
    let { data: user } = await app.supabase
      .from('users')
      .select('id, role')
      .eq('email', email)
      .maybeSingle()

    if (!user) {
      const { data: newUser, error } = await app.supabase
        .from('users')
        .insert({ email, role: role ?? 'shipper', email_verified: false })
        .select('id, role')
        .single()
      if (error || !newUser) {
        return reply.status(500).send({ success: false, error: 'Failed to create account' })
      }
      user = newUser
    }

    const linkToken = jwt.sign(
      { userId: user.id, role: user.role, type: 'magic' },
      process.env.JWT_SECRET!,
      { expiresIn: MAGIC_TTL_S },
    )
    await app.redis.set(`magic:${user.id}`, linkToken, 'EX', MAGIC_TTL_S)

    // Prefer the callback URL provided by the frontend (it knows its own origin).
    // Fall back to per-role env vars so production deployments can override without a code change.
    const defaultRedirect = (user.role ?? role) === 'driver'
      ? (process.env.DRIVER_MAGIC_LINK_URL ?? 'http://localhost:3002/auth/callback')
      : (process.env.SHIPPER_MAGIC_LINK_URL ?? 'http://localhost:3000/auth/callback')
    const redirectBase = callback_url ?? defaultRedirect
    const link = `${redirectBase}?token=${encodeURIComponent(linkToken)}`
    await sendMagicLinkEmail(email, link)

    return reply.send({ success: true, data: { message: 'Sign-in link sent', expires_in: MAGIC_TTL_S } })
  })

  // ── GET /auth/magic-link/verify ──────────────────────────────────────────────

  app.get('/magic-link/verify', async (req, reply) => {
    const { token } = (req.query as Record<string, string>)
    if (!token) {
      return reply.status(400).send({ success: false, error: 'Missing token' })
    }

    let payload: JwtPayload & { type?: string }
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload & { type?: string }
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid or expired magic link' })
    }

    if (payload.type !== 'magic') {
      return reply.status(401).send({ success: false, error: 'Invalid token type' })
    }

    const stored = await app.redis.get(`magic:${payload.userId}`)
    if (!stored || stored !== token) {
      return reply.status(401).send({ success: false, error: 'Magic link already used or expired' })
    }
    await app.redis.del(`magic:${payload.userId}`)

    const { data: user, error } = await app.supabase
      .from('users')
      .update({ email_verified: true })
      .eq('id', payload.userId)
      .select('*')
      .single()
    if (error || !user) {
      return reply.status(404).send({ success: false, error: 'User not found' })
    }

    const { access_token, refresh_token } = issueTokens(user.id, user.role)
    await app.redis.set(`refresh:${user.id}`, refresh_token, 'EX', REFRESH_TTL_S)

    return reply.send({
      success: true,
      data: {
        access_token,
        refresh_token,
        is_new_user: false,
        user: userProfile(user),
      },
    })
  })

  // ── POST /auth/google ────────────────────────────────────────────────────────

  app.post('/google', async (req, reply) => {
    const body = GoogleSignInBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { id_token, role } = body.data

    if (!process.env.GOOGLE_CLIENT_ID) {
      return reply.status(501).send({ success: false, error: 'Google sign-in not configured' })
    }

    let googlePayload: { sub: string; email?: string; name?: string; picture?: string }
    try {
      const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
      const ticket = await client.verifyIdToken({ idToken: id_token, audience: process.env.GOOGLE_CLIENT_ID })
      const p = ticket.getPayload()
      if (!p) throw new Error('Empty payload')
      googlePayload = { sub: p.sub, email: p.email, name: p.name, picture: p.picture }
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid Google token' })
    }

    // Look up by google_sub first, then by email
    let { data: user } = await app.supabase
      .from('users')
      .select('*')
      .eq('google_sub', googlePayload.sub)
      .maybeSingle()

    let is_new_user = false

    if (!user && googlePayload.email) {
      const { data: emailUser } = await app.supabase
        .from('users')
        .select('*')
        .eq('email', googlePayload.email)
        .maybeSingle()

      if (emailUser) {
        // Link Google to existing account
        const { data: linked } = await app.supabase
          .from('users')
          .update({
            google_sub:     googlePayload.sub,
            avatar_url:     googlePayload.picture ?? emailUser.avatar_url,
            full_name:      emailUser.full_name ?? googlePayload.name,
            email_verified: true,
          })
          .eq('id', emailUser.id)
          .select('*')
          .single()
        user = linked ?? emailUser
      }
    }

    if (!user) {
      is_new_user = true
      const { data: newUser, error } = await app.supabase
        .from('users')
        .insert({
          email:          googlePayload.email ?? null,
          full_name:      googlePayload.name ?? null,
          avatar_url:     googlePayload.picture ?? null,
          google_sub:     googlePayload.sub,
          role:           role ?? 'shipper',
          email_verified: true,
        })
        .select('*')
        .single()
      if (error || !newUser) {
        return reply.status(500).send({ success: false, error: 'Failed to create account' })
      }
      user = newUser

      if (user.role === 'driver') {
        await app.supabase.from('drivers').upsert({ user_id: user.id }, { onConflict: 'user_id' })
      }
    }

    const { access_token, refresh_token } = issueTokens(user.id, user.role)
    await app.redis.set(`refresh:${user.id}`, refresh_token, 'EX', REFRESH_TTL_S)

    return reply.send({
      success: true,
      data: {
        access_token,
        refresh_token,
        is_new_user,
        user: userProfile(user),
      },
    })
  })

  // ── POST /auth/refresh ───────────────────────────────────────────────────────

  app.post('/refresh', async (req, reply) => {
    const body = RefreshBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { refresh_token } = body.data

    let payload: JwtPayload
    try {
      payload = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET!) as JwtPayload
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid or expired refresh token' })
    }

    const stored = await app.redis.get(`refresh:${payload.userId}`)
    if (!stored || stored !== refresh_token) {
      return reply.status(401).send({ success: false, error: 'Refresh token revoked or not found' })
    }

    const access_token = jwt.sign(
      { userId: payload.userId, role: payload.role } satisfies JwtPayload,
      process.env.JWT_SECRET!,
      { expiresIn: ACCESS_TTL_S },
    )

    return reply.send({ success: true, data: { access_token } })
  })

  // ── GET /auth/me ─────────────────────────────────────────────────────────────

  app.get('/me', { preHandler: authenticate }, async (req, reply) => {
    const { data: user } = await app.supabase
      .from('users')
      .select('*')
      .eq('id', req.user.userId)
      .maybeSingle()

    if (!user) {
      return reply.status(404).send({ success: false, error: 'User not found' })
    }

    return reply.send({ success: true, data: { user: userProfile(user) } })
  })

  // ── POST /auth/register ──────────────────────────────────────────────────────
  // Called after first phone-OTP login to set profile + role

  app.post('/register', { preHandler: authenticate }, async (req, reply) => {
    const body = RegisterProfileBody.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    }
    const { full_name, role, email } = body.data

    const { data: user, error } = await app.supabase
      .from('users')
      .update({ full_name, role, ...(email ? { email } : {}) })
      .eq('id', req.user.userId)
      .select('*')
      .single()
    if (error || !user) {
      return reply.status(500).send({ success: false, error: 'Failed to update profile' })
    }

    if (role === 'driver') {
      await app.supabase.from('drivers').upsert({ user_id: user.id }, { onConflict: 'user_id' })
    }

    return reply.send({ success: true, data: { user: userProfile(user) } })
  })

  // ── POST /auth/logout ────────────────────────────────────────────────────────

  app.post('/logout', { preHandler: authenticate }, async (req, reply) => {
    await app.redis.del(`refresh:${req.user.userId}`)
    return reply.send({ success: true, data: { message: 'Logged out' } })
  })
}
