import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { generateOtp, sendOtp } from '../lib/otp.js'
import { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken } from '../lib/jwt.js'
import { verifyGoogleToken } from '../lib/google.js'
import { hashPassword, verifyPassword } from '../lib/password.js'
import { sendEmailOtp, sendMagicLinkEmail } from '../lib/email.js'
import crypto from 'crypto'

const OTP_TTL = 300
const EMAIL_OTP_TTL = 600 // 10 minutes for email verification
const MAGIC_LINK_TTL = 900 // 15 minutes
const otpKey = (phone: string) => `otp:${phone}`
const attemptsKey = (phone: string) => `otp_attempts:${phone}`
const emailOtpKey = (email: string) => `email_otp:${email}`
const emailAttemptsKey = (email: string) => `email_otp_attempts:${email}`
const magicLinkKey = (token: string) => `magic_link:${token}`
const magicLinkAttemptsKey = (email: string) => `magic_link_attempts:${email}`

const phoneSchema = z.string().refine(
  v => /^[6-9]\d{9}$/.test(v) || v === '+14782159223' || v === '+18777804236',
  'Invalid Indian mobile number'
)
const SdendOtpBody   = z.object({ phone: phoneSchema })
const VerifyOtpBody = z.object({ phone: phoneSchema, otp: z.string().length(6) })
const RegisterBody  = z.object({
  full_name: z.string().min(2).max(100).optional(),
  name: z.string().min(2).max(100).optional(),
  role: z.enum(['shipper', 'driver']),
  email: z.string().email().optional(),
  // driver fields
  truck_number: z.string().optional(),
  truck_type: z.string().optional(),
  vehicle_number: z.string().optional(),
  vehicle_type: z.string().optional(),
  license_number: z.string().optional(),
  // fleet owner fields
  company_name: z.string().optional(),
}).refine(d => d.full_name || d.name, { message: 'full_name is required' })

export async function authRoutes(app: FastifyInstance) {

  // POST /auth/send-otp
  app.post('/send-otp', async (req, reply) => {
    const body = SdendOtpBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { phone } = body.data
    const attempts = await app.redis.incr(attemptsKey(phone))
    if (attempts === 1) await app.redis.expire(attemptsKey(phone), 3600)
    if (process.env.NODE_ENV !== 'development' && attempts > 5) return reply.status(429).send({ success: false, error: 'Too many requests. Try after 1 hour.' })
    const otp = generateOtp()
    await app.redis.setex(otpKey(phone), OTP_TTL, otp)
    await sendOtp(phone, otp)
    return reply.send({ success: true, data: { message: 'OTP sent', expires_in: OTP_TTL } })
  })

  // POST /auth/verify-otp
  app.post('/verify-otp', async (req, reply) => {
    const body = VerifyOtpBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { phone, otp } = body.data
    const stored = await app.redis.get(otpKey(phone))
    if (!stored || stored !== otp) return reply.status(401).send({ success: false, error: 'Invalid or expired OTP' })
    await app.redis.del(otpKey(phone))

    const { data: existing } = await app.supabase
      .from('users').select('*').eq('phone', phone).maybeSingle()
    let user = existing
    if (!user) {
      const { data: created, error } = await app.supabase
        .from('users').insert({ phone: phone, role: 'shipper' }).select().single()
      if (error || !created) return reply.status(500).send({ success: false, error: 'Failed to create user' })
      user = created
    }

    const payload = { userId: user.id, phone: user.phone, role: user.role }
    const accessToken = signAccessToken(payload)
    const refreshToken = signRefreshToken(payload)
    await app.redis.setex(`refresh:${user.id}`, 7 * 86400, refreshToken)

    return reply.send({
      success: true,
      data: { access_token: accessToken, refresh_token: refreshToken, is_new_user: !existing, user },
    })
  })

  // POST /auth/refresh
  app.post('/refresh', async (req, reply) => {
    const { refresh_token } = (req.body as any) ?? {}
    if (!refresh_token) return reply.status(400).send({ success: false, error: 'refresh_token required' })
    try {
      const decoded = verifyRefreshToken(refresh_token)
      const stored = await app.redis.get(`refresh:${decoded.userId}`)
      if (!stored || stored !== refresh_token) return reply.status(401).send({ success: false, error: 'Token revoked' })
      const { userId, phone, role } = decoded
      return reply.send({ success: true, data: { access_token: signAccessToken({ userId, phone, role }) } })
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid refresh token' })
    }
  })

  // POST /auth/register  — complete profile after first OTP verify
  app.post('/register', async (req, reply) => {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return reply.status(401).send({ success: false, error: 'Authorization required' })
    let jwtPayload: ReturnType<typeof verifyAccessToken>
    try { jwtPayload = verifyAccessToken(token) } catch { return reply.status(401).send({ success: false, error: 'Invalid token' }) }

    const body = RegisterBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { role, email, license_number, company_name } = body.data
    const truck_number = body.data.truck_number ?? body.data.vehicle_number
    const truck_type = body.data.truck_type ?? body.data.vehicle_type
    const full_name = body.data.full_name ?? body.data.name

    const { error: userErr } = await app.supabase
      .from('users')
      .update({ full_name, role, email })
      .eq('id', jwtPayload.userId)
    if (userErr) return reply.status(500).send({ success: false, error: 'Failed to update profile' })

    if (role === 'driver') {
      await app.supabase.from('drivers').upsert({
        user_id: jwtPayload.userId,
        truck_number,
        truck_type,
        license_number,
      })
    }

    const { data: user } = await app.supabase
      .from('users').select('*, drivers(*)').eq('id', jwtPayload.userId).single()

    return reply.send({ success: true, data: { user } })
  })

  // GET /auth/me
  app.get('/me', async (req, reply) => {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return reply.status(401).send({ success: false, error: 'Authorization required' })
    try {
      const { userId } = verifyAccessToken(token)
      const { data: user } = await app.supabase
        .from('users').select('*, drivers(*)').eq('id', userId).single()
      if (!user) return reply.status(404).send({ success: false, error: 'User not found' })
      return reply.send({ success: true, data: { user } })
    } catch { return reply.status(401).send({ success: false, error: 'Invalid token' }) }
  })

  // POST /auth/google  — Sign In / Sign Up with Google
  app.post('/google', async (req, reply) => {
    const { id_token, role } = (req.body as any) ?? {}
    if (!id_token) return reply.status(400).send({ success: false, error: 'id_token required' })

    let googleUser
    try {
      googleUser = await verifyGoogleToken(id_token)
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid Google token' })
    }

    let { data: existing } = await app.supabase
      .from('users').select('*, drivers(*)').eq('google_sub', googleUser.sub).maybeSingle()

    if (!existing) {
      const { data: byEmail } = await app.supabase
        .from('users').select('*, drivers(*)').eq('email', googleUser.email).maybeSingle()
      existing = byEmail
    }

    let user = existing
    const isNewUser = !existing

    if (isNewUser) {
      const resolvedRole = role === 'driver' ? 'driver' : 'shipper'
      const { data: created, error } = await app.supabase
        .from('users')
        .insert({
          google_sub: googleUser.sub,
          email: googleUser.email,
          full_name: googleUser.name,
          avatar_url: googleUser.picture,
          role: resolvedRole,
        })
        .select('*, drivers(*)')
        .single()
      if (error || !created) return reply.status(500).send({ success: false, error: 'Failed to create user' })
      user = created
    } else if (!existing.google_sub) {
      await app.supabase
        .from('users')
        .update({ google_sub: googleUser.sub, avatar_url: googleUser.picture, full_name: googleUser.name })
        .eq('id', existing.id)
      user = { ...existing, google_sub: googleUser.sub, avatar_url: googleUser.picture, full_name: googleUser.name }
    }

    const payload = { userId: user.id, phone: user.phone ?? undefined, role: user.role }
    const accessToken = signAccessToken(payload)
    const refreshToken = signRefreshToken(payload)
    await app.redis.setex(`refresh:${user.id}`, 7 * 86400, refreshToken)

    return reply.send({
      success: true,
      data: { access_token: accessToken, refresh_token: refreshToken, is_new_user: isNewUser, user },
    })
  })

  // ── Email/Password Auth ──────────────────────────────────────────────────

  const EmailRegisterBody = z.object({
    email: z.string().email(),
    password: z.string().min(8).max(128),
    full_name: z.string().min(2).max(100),
    role: z.enum(['shipper', 'driver']).default('shipper'),
  })

  const EmailLoginBody = z.object({
    email: z.string().email(),
    password: z.string().min(1),
  })

  const EmailOtpBody = z.object({
    email: z.string().email(),
    otp: z.string().length(6),
  })

  // POST /auth/email/register — create account with email + password, sends verification OTP
  app.post('/email/register', async (req, reply) => {
    const body = EmailRegisterBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { email, password, full_name, role } = body.data

    // Check if email is already taken
    const { data: existing } = await app.supabase
      .from('users').select('id, email_verified').eq('email', email).maybeSingle()

    if (existing?.email_verified) {
      return reply.status(409).send({ success: false, error: 'Email already registered' })
    }

    const password_hash = await hashPassword(password)

    let user
    if (existing && !existing.email_verified) {
      // User exists but never verified — update their password and resend OTP
      const { data: updated, error } = await app.supabase
        .from('users')
        .update({ password_hash, full_name, role })
        .eq('id', existing.id)
        .select()
        .single()
      if (error || !updated) return reply.status(500).send({ success: false, error: 'Failed to update user' })
      user = updated
    } else {
      // Create new user
      const { data: created, error } = await app.supabase
        .from('users')
        .insert({ email, password_hash, full_name, role, email_verified: false })
        .select()
        .single()
      if (error || !created) return reply.status(500).send({ success: false, error: 'Failed to create user' })
      user = created
    }

    // Generate and send email verification OTP
    const otp = generateOtp()
    await app.redis.setex(emailOtpKey(email), EMAIL_OTP_TTL, otp)
    await sendEmailOtp(email, otp)

    return reply.status(201).send({
      success: true,
      data: {
        message: 'Account created. Verification OTP sent to your email.',
        email_verified: false,
        user_id: user.id,
        expires_in: EMAIL_OTP_TTL,
      },
    })
  })

  // POST /auth/email/verify — verify email with OTP (first-time only)
  app.post('/email/verify', async (req, reply) => {
    const body = EmailOtpBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { email, otp } = body.data

    const stored = await app.redis.get(emailOtpKey(email))
    if (!stored || stored !== otp) {
      return reply.status(401).send({ success: false, error: 'Invalid or expired OTP' })
    }
    await app.redis.del(emailOtpKey(email))

    // Mark email as verified
    const { data: user, error } = await app.supabase
      .from('users')
      .update({ email_verified: true })
      .eq('email', email)
      .select('*, drivers(*)')
      .single()
    if (error || !user) return reply.status(500).send({ success: false, error: 'Failed to verify email' })

    // Issue tokens — user is now fully authenticated
    const payload = { userId: user.id, phone: user.phone ?? undefined, role: user.role }
    const accessToken = signAccessToken(payload)
    const refreshToken = signRefreshToken(payload)
    await app.redis.setex(`refresh:${user.id}`, 7 * 86400, refreshToken)

    return reply.send({
      success: true,
      data: { access_token: accessToken, refresh_token: refreshToken, is_new_user: true, user },
    })
  })

  // POST /auth/email/resend-otp — resend verification OTP
  app.post('/email/resend-otp', async (req, reply) => {
    const body = z.object({ email: z.string().email() }).safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { email } = body.data

    const { data: user } = await app.supabase
      .from('users').select('id, email_verified').eq('email', email).maybeSingle()
    if (!user) return reply.status(404).send({ success: false, error: 'No account found with this email' })
    if (user.email_verified) return reply.status(400).send({ success: false, error: 'Email is already verified' })

    // Rate limit
    const attempts = await app.redis.incr(emailAttemptsKey(email))
    if (attempts === 1) await app.redis.expire(emailAttemptsKey(email), 3600)
    if (attempts > 5) return reply.status(429).send({ success: false, error: 'Too many requests. Try after 1 hour.' })

    const otp = generateOtp()
    await app.redis.setex(emailOtpKey(email), EMAIL_OTP_TTL, otp)
    await sendEmailOtp(email, otp)

    return reply.send({ success: true, data: { message: 'Verification OTP resent', expires_in: EMAIL_OTP_TTL } })
  })

  // POST /auth/email/login — login with email + password (must be verified)
  app.post('/email/login', async (req, reply) => {
    const body = EmailLoginBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { email, password } = body.data

    const { data: user } = await app.supabase
      .from('users').select('*, drivers(*)').eq('email', email).maybeSingle()

    if (!user || !user.password_hash) {
      return reply.status(401).send({ success: false, error: 'Invalid email or password' })
    }

    const valid = await verifyPassword(password, user.password_hash)
    if (!valid) return reply.status(401).send({ success: false, error: 'Invalid email or password' })

    if (!user.email_verified) {
      // Auto-send a new verification OTP
      const otp = generateOtp()
      await app.redis.setex(emailOtpKey(email), EMAIL_OTP_TTL, otp)
      await sendEmailOtp(email, otp)

      return reply.status(403).send({
        success: false,
        error: 'Email not verified. A new verification OTP has been sent.',
        data: { email_verified: false, expires_in: EMAIL_OTP_TTL },
      })
    }

    // Verified user — issue tokens directly, no OTP needed
    const payload = { userId: user.id, phone: user.phone ?? undefined, role: user.role }
    const accessToken = signAccessToken(payload)
    const refreshToken = signRefreshToken(payload)
    await app.redis.setex(`refresh:${user.id}`, 7 * 86400, refreshToken)

    return reply.send({
      success: true,
      data: { access_token: accessToken, refresh_token: refreshToken, is_new_user: false, user },
    })
  })

  // ── Magic Link Auth ────────────────────────────────────────────────────

  const MagicLinkSendBody = z.object({
    email: z.string().email(),
    role: z.enum(['shipper', 'driver']).default('shipper'),
  })

  const MagicLinkVerifyBody = z.object({
    token: z.string().min(1),
  })

  // POST /auth/magic-link/send — send a magic link to the user's email
  app.post('/magic-link/send', async (req, reply) => {
    const body = MagicLinkSendBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    const { email, role } = body.data

    // Rate limit
    const attempts = await app.redis.incr(magicLinkAttemptsKey(email))
    if (attempts === 1) await app.redis.expire(magicLinkAttemptsKey(email), 3600)
    if (attempts > 5) return reply.status(429).send({ success: false, error: 'Too many requests. Try after 1 hour.' })

    // Generate a secure token and store email + role in Redis
    const token = crypto.randomBytes(32).toString('hex')
    await app.redis.setex(magicLinkKey(token), MAGIC_LINK_TTL, JSON.stringify({ email, role }))

    // If a frontend redirect URL is set, the magic link opens the frontend which calls the API to verify
    // Otherwise, the link goes directly to the API verify endpoint
    const frontendUrl = process.env.MAGIC_LINK_REDIRECT_URL
    const baseUrl = process.env.MAGIC_LINK_BASE_URL ?? 'http://localhost:3001'
    const link = frontendUrl
      ? `${frontendUrl}?token=${token}`
      : `${baseUrl}/auth/magic-link/verify?token=${token}`

    await sendMagicLinkEmail(email, link)

    return reply.send({
      success: true,
      data: { message: 'Magic link sent to your email', expires_in: MAGIC_LINK_TTL },
    })
  })

  // GET /auth/magic-link/verify — verify the magic link token and create session
  app.get('/magic-link/verify', async (req, reply) => {
    const { token } = req.query as { token?: string }
    if (!token) return reply.status(400).send({ success: false, error: 'Token required' })

    const stored = await app.redis.get(magicLinkKey(token))
    if (!stored) return reply.status(401).send({ success: false, error: 'Invalid or expired magic link' })

    // Delete token immediately — single use
    await app.redis.del(magicLinkKey(token))

    const { email, role } = JSON.parse(stored) as { email: string; role: string }

    // Find or create user
    let { data: user } = await app.supabase
      .from('users').select('*, drivers(*)').eq('email', email).maybeSingle()

    const isNewUser = !user
    if (!user) {
      const { data: created, error } = await app.supabase
        .from('users')
        .insert({ email, role, email_verified: true })
        .select('*, drivers(*)')
        .single()
      if (error || !created) return reply.status(500).send({ success: false, error: 'Failed to create user' })
      user = created
    } else if (!user.email_verified) {
      await app.supabase.from('users').update({ email_verified: true }).eq('id', user.id)
      user = { ...user, email_verified: true }
    }

    const payload = { userId: user.id, phone: user.phone ?? undefined, role: user.role }
    const accessToken = signAccessToken(payload)
    const refreshToken = signRefreshToken(payload)
    await app.redis.setex(`refresh:${user.id}`, 7 * 86400, refreshToken)

    return reply.send({
      success: true,
      data: { access_token: accessToken, refresh_token: refreshToken, is_new_user: isNewUser, user },
    })
  })

  // POST /auth/logout
  app.post('/logout', async (req, reply) => {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (token) {
      try { const { userId } = verifyAccessToken(token); await app.redis.del(`refresh:${userId}`) } catch {}
    }
    return reply.send({ success: true, data: { message: 'Logged out' } })
  })
}
