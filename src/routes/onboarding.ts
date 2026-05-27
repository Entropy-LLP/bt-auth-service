import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { authenticate } from '../lib/authenticate.js'
import { encrypt } from '../lib/encryption.js'

const UpdateProfileBody = z.object({
  full_name:      z.string().min(2).max(100).optional(),
  photo_url:      z.string().url().optional(),
  languages:      z.array(z.string().min(1).max(30)).max(10).optional(),
  home_base_city: z.string().min(1).max(100).optional(),
  home_base_lat:  z.number().min(-90).max(90).optional(),
  home_base_lng:  z.number().min(-180).max(180).optional(),
})

const CreateVehicleBody = z.object({
  rc_number:       z.string().min(4).max(20),
  rc_storage_path: z.string().optional(),
  vehicle_photos:  z.array(z.string()).max(10).optional(),
  capacity_tons:   z.number().positive().max(100).optional(),
  body_type:       z.enum(['open', 'closed', 'container', 'flatbed', 'tanker', 'refrigerated']).optional(),
  axle_config:     z.enum(['4x2', '6x2', '6x4', '8x4', '10x2']).optional(),
  maker_model:     z.string().max(100).optional(),
  fuel_type:       z.string().max(20).optional(),
  rc_expiry:       z.string().date().optional(),
})

const UpdateVehicleBody = CreateVehicleBody.partial()

const UuidParam = z.object({ id: z.string().uuid() })

const SubmitLicenseBody = z.object({
  dl_number:       z.string().min(5).max(30),
  dl_storage_path: z.string().optional(),
  vehicle_classes: z.array(z.string().max(10)).max(10).optional(),
  expiry_date:     z.string().date().optional(),
})

const UpdateLicenseBody = SubmitLicenseBody.partial()

const SubmitInsuranceBody = z.object({
  policy_number: z.string().min(1).max(50),
  provider:      z.string().max(100).optional(),
  storage_path:  z.string().optional(),
  expiry_date:   z.string().date().optional(),
})

const LinkBankAccountBody = z.object({
  account_number:      z.string().min(8).max(18),
  ifsc:                z.string().regex(/^[A-Z]{4}0[A-Z0-9]{6}$/, 'Invalid IFSC code'),
  bank_name:           z.string().max(100).optional(),
  account_holder_name: z.string().min(2).max(100),
  is_primary:          z.boolean().optional(),
})

function driverOnly(role: string): string | null {
  return role === 'driver' ? null : 'Only drivers can access onboarding'
}

type VerificationBadge = 'pending' | 'verified' | 'premium'

interface BadgeInput {
  driver: Record<string, unknown> | null
  license: { status: string } | null
  vehicleCount: number
  verifiedVehicleCount: number
  bankLinked: boolean
  insuranceCount: number
  kycStatus: string
}

function computeBadge(input: BadgeInput): VerificationBadge {
  const { driver, license, verifiedVehicleCount, bankLinked, insuranceCount, kycStatus } = input
  if (!driver) return 'pending'

  const profileComplete = !!(
    driver.photo_url &&
    (driver.languages as string[] | undefined)?.length &&
    driver.home_base_city
  )
  const isVerified = profileComplete && license?.status === 'verified' && verifiedVehicleCount > 0 && bankLinked
  if (!isVerified) return 'pending'

  const isPremium = insuranceCount > 0 && (kycStatus === 'verified' || kycStatus === 'approved')
  return isPremium ? 'premium' : 'verified'
}

export async function onboardingRoutes(app: FastifyInstance) {

  // PUT /onboarding/profile
  app.put('/profile', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const body = UpdateProfileBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })

    const { full_name, ...driverFields } = body.data

    if (full_name) {
      const { error: userErr } = await app.supabase
        .from('users').update({ full_name }).eq('id', req.user.userId)
      if (userErr) return reply.status(500).send({ success: false, error: 'Failed to update user name' })
    }

    if (Object.keys(driverFields).length > 0) {
      const { error: driverErr } = await app.supabase
        .from('drivers').update(driverFields).eq('user_id', req.user.userId)
      if (driverErr) return reply.status(500).send({ success: false, error: 'Failed to update driver profile' })
    }

    const { data: driver } = await app.supabase
      .from('drivers').select('*').eq('user_id', req.user.userId).single()

    return reply.send({ success: true, data: { driver } })
  })

  // GET /onboarding/profile
  app.get('/profile', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const { data: user } = await app.supabase
      .from('users')
      .select('id, full_name, phone_number, email, avatar_url, city, state, kyc_status')
      .eq('id', req.user.userId)
      .single()
    if (!user) return reply.status(404).send({ success: false, error: 'User not found' })

    const { data: driver } = await app.supabase
      .from('drivers').select('*').eq('user_id', req.user.userId).single()

    const { data: license } = await app.supabase
      .from('driver_licenses').select('*').eq('driver_id', driver?.id).maybeSingle()

    const { data: vehicles } = await app.supabase
      .from('vehicles').select('*, driver_insurance(*)').eq('driver_id', driver?.id)

    const { data: bankAccounts } = await app.supabase
      .from('bank_accounts')
      .select('id, account_number_last4, ifsc, bank_name, account_holder_name, is_primary, verification_status')
      .eq('user_id', req.user.userId)

    return reply.send({
      success: true,
      data: { user, driver, license, vehicles: vehicles ?? [], bank_accounts: bankAccounts ?? [] },
    })
  })

  // POST /onboarding/vehicle
  app.post('/vehicle', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const body = CreateVehicleBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found. Complete registration first.' })

    const { data: existing } = await app.supabase
      .from('vehicles').select('id').eq('rc_number', body.data.rc_number).maybeSingle()
    if (existing) return reply.status(409).send({ success: false, error: 'Vehicle with this RC number already registered' })

    const { data: vehicle, error } = await app.supabase
      .from('vehicles').insert({ driver_id: driver.id, ...body.data }).select().single()
    if (error) return reply.status(500).send({ success: false, error: 'Failed to register vehicle' })

    return reply.status(201).send({ success: true, data: { vehicle } })
  })

  // PUT /onboarding/vehicle/:id
  app.put<{ Params: { id: string } }>('/vehicle/:id', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const params = UuidParam.safeParse(req.params)
    if (!params.success) return reply.status(400).send({ success: false, error: 'Invalid vehicle id' })

    const body = UpdateVehicleBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    if (Object.keys(body.data).length === 0) return reply.status(400).send({ success: false, error: 'No fields to update' })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found' })

    const { data: vehicle } = await app.supabase
      .from('vehicles').select('id').eq('id', params.data.id).eq('driver_id', driver.id).maybeSingle()
    if (!vehicle) return reply.status(404).send({ success: false, error: 'Vehicle not found' })

    if (body.data.rc_number) {
      const { data: dup } = await app.supabase
        .from('vehicles').select('id').eq('rc_number', body.data.rc_number).neq('id', params.data.id).maybeSingle()
      if (dup) return reply.status(409).send({ success: false, error: 'Another vehicle with this RC number already exists' })
    }

    const { data: updated, error } = await app.supabase
      .from('vehicles').update(body.data).eq('id', params.data.id).select().single()
    if (error) return reply.status(500).send({ success: false, error: 'Failed to update vehicle' })

    return reply.send({ success: true, data: { vehicle: updated } })
  })

  // GET /onboarding/vehicles
  app.get('/vehicles', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found' })

    const { data: vehicles } = await app.supabase
      .from('vehicles').select('*, driver_insurance(*)').eq('driver_id', driver.id)
      .order('created_at', { ascending: false })

    return reply.send({ success: true, data: { vehicles: vehicles ?? [] } })
  })

  // POST /onboarding/license
  app.post('/license', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const body = SubmitLicenseBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found' })

    const { data: existing } = await app.supabase
      .from('driver_licenses').select('id').eq('driver_id', driver.id).maybeSingle()
    if (existing) return reply.status(409).send({ success: false, error: 'License already submitted. Use PUT to update.' })

    const { data: dupDl } = await app.supabase
      .from('driver_licenses').select('id').eq('dl_number', body.data.dl_number).maybeSingle()
    if (dupDl) return reply.status(409).send({ success: false, error: 'This DL number is already registered by another driver' })

    const { data: license, error } = await app.supabase
      .from('driver_licenses').insert({ driver_id: driver.id, ...body.data }).select().single()
    if (error) return reply.status(500).send({ success: false, error: 'Failed to submit license' })

    return reply.status(201).send({ success: true, data: { license } })
  })

  // PUT /onboarding/license
  app.put('/license', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const body = UpdateLicenseBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })
    if (Object.keys(body.data).length === 0) return reply.status(400).send({ success: false, error: 'No fields to update' })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found' })

    if (body.data.dl_number) {
      const { data: dup } = await app.supabase
        .from('driver_licenses').select('id').eq('dl_number', body.data.dl_number).neq('driver_id', driver.id).maybeSingle()
      if (dup) return reply.status(409).send({ success: false, error: 'This DL number is already registered by another driver' })
    }

    const { data: license, error } = await app.supabase
      .from('driver_licenses').update({ ...body.data, status: 'pending' }).eq('driver_id', driver.id).select().single()
    if (error) return reply.status(404).send({ success: false, error: 'No license found to update. Submit one first.' })

    return reply.send({ success: true, data: { license } })
  })

  // POST /onboarding/vehicle/:id/insurance
  app.post<{ Params: { id: string } }>('/vehicle/:id/insurance', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const params = UuidParam.safeParse(req.params)
    if (!params.success) return reply.status(400).send({ success: false, error: 'Invalid vehicle id' })

    const body = SubmitInsuranceBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })

    const { data: driver } = await app.supabase
      .from('drivers').select('id').eq('user_id', req.user.userId).single()
    if (!driver) return reply.status(404).send({ success: false, error: 'Driver profile not found' })

    const { data: vehicle } = await app.supabase
      .from('vehicles').select('id').eq('id', params.data.id).eq('driver_id', driver.id).maybeSingle()
    if (!vehicle) return reply.status(404).send({ success: false, error: 'Vehicle not found' })

    const { data: insurance, error } = await app.supabase
      .from('driver_insurance')
      .insert({ driver_id: driver.id, vehicle_id: params.data.id, ...body.data })
      .select().single()
    if (error) {
      if (error.code === '23505') return reply.status(409).send({ success: false, error: 'Insurance with this policy number already exists for this vehicle' })
      return reply.status(500).send({ success: false, error: 'Failed to submit insurance' })
    }

    return reply.status(201).send({ success: true, data: { insurance } })
  })

  // POST /onboarding/bank-account
  app.post('/bank-account', { preHandler: authenticate }, async (req, reply) => {
    const body = LinkBankAccountBody.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ success: false, error: body.error.errors[0].message })

    const { account_number, ifsc, bank_name, account_holder_name, is_primary } = body.data
    const last4 = account_number.slice(-4)

    let encrypted: string
    try {
      encrypted = encrypt(account_number)
    } catch (e) {
      app.log.error(e, 'Encryption failed')
      return reply.status(500).send({ success: false, error: 'Failed to secure account details' })
    }

    if (is_primary !== false) {
      await app.supabase
        .from('bank_accounts').update({ is_primary: false })
        .eq('user_id', req.user.userId).eq('is_primary', true)
    }

    const { data: account, error } = await app.supabase
      .from('bank_accounts')
      .insert({
        user_id: req.user.userId,
        account_number_enc: encrypted,
        account_number_last4: last4,
        ifsc,
        bank_name: bank_name ?? null,
        account_holder_name,
        is_primary: is_primary !== false,
      })
      .select('id, account_number_last4, ifsc, bank_name, account_holder_name, is_primary, verification_status, created_at')
      .single()
    if (error) return reply.status(500).send({ success: false, error: 'Failed to link bank account' })

    return reply.status(201).send({ success: true, data: { bank_account: account } })
  })

  // GET /onboarding/bank-accounts
  app.get('/bank-accounts', { preHandler: authenticate }, async (req, reply) => {
    const { data: accounts } = await app.supabase
      .from('bank_accounts')
      .select('id, account_number_last4, ifsc, bank_name, account_holder_name, is_primary, verification_status, created_at')
      .eq('user_id', req.user.userId)
      .order('is_primary', { ascending: false })
      .order('created_at', { ascending: false })

    return reply.send({ success: true, data: { bank_accounts: accounts ?? [] } })
  })

  // DELETE /onboarding/bank-account/:id
  app.delete<{ Params: { id: string } }>('/bank-account/:id', { preHandler: authenticate }, async (req, reply) => {
    const params = UuidParam.safeParse(req.params)
    if (!params.success) return reply.status(400).send({ success: false, error: 'Invalid account id' })

    const { data: account } = await app.supabase
      .from('bank_accounts').select('id, is_primary')
      .eq('id', params.data.id).eq('user_id', req.user.userId).maybeSingle()
    if (!account) return reply.status(404).send({ success: false, error: 'Bank account not found' })

    const { error } = await app.supabase
      .from('bank_accounts').delete().eq('id', params.data.id)
    if (error) return reply.status(500).send({ success: false, error: 'Failed to remove bank account' })

    if (account.is_primary) {
      const { data: next } = await app.supabase
        .from('bank_accounts').select('id')
        .eq('user_id', req.user.userId).order('created_at', { ascending: false }).limit(1).maybeSingle()
      if (next) {
        await app.supabase.from('bank_accounts').update({ is_primary: true }).eq('id', next.id)
      }
    }

    return reply.send({ success: true, data: { message: 'Bank account removed' } })
  })

  // GET /onboarding/status
  app.get('/status', { preHandler: authenticate }, async (req, reply) => {
    const err = driverOnly(req.user.role)
    if (err) return reply.status(403).send({ success: false, error: err })

    const { data: user } = await app.supabase
      .from('users').select('kyc_status').eq('id', req.user.userId).single()

    const { data: driver } = await app.supabase
      .from('drivers').select('id, photo_url, languages, home_base_city, verification_badge')
      .eq('user_id', req.user.userId).single()

    if (!driver) {
      return reply.send({
        success: true,
        data: {
          verification_badge: 'pending' as VerificationBadge,
          checklist: {
            profile_complete: false,
            license_submitted: false,
            license_verified: false,
            vehicle_registered: false,
            vehicle_verified: false,
            insurance_uploaded: false,
            bank_linked: false,
          },
        },
      })
    }

    const { data: license } = await app.supabase
      .from('driver_licenses').select('status').eq('driver_id', driver.id).maybeSingle()

    const { data: vehicles } = await app.supabase
      .from('vehicles').select('id, rc_status').eq('driver_id', driver.id)

    const { count: insuranceCount } = await app.supabase
      .from('driver_insurance').select('id', { count: 'exact', head: true }).eq('driver_id', driver.id)

    const { count: bankCount } = await app.supabase
      .from('bank_accounts').select('id', { count: 'exact', head: true }).eq('user_id', req.user.userId)

    const vehicleList = vehicles ?? []
    const verifiedVehicles = vehicleList.filter(v => v.rc_status === 'verified').length
    const bankLinked = (bankCount ?? 0) > 0

    const badge = computeBadge({
      driver,
      license,
      vehicleCount: vehicleList.length,
      verifiedVehicleCount: verifiedVehicles,
      bankLinked,
      insuranceCount: insuranceCount ?? 0,
      kycStatus: user?.kyc_status ?? 'pending',
    })

    if (badge !== (driver as Record<string, unknown>).verification_badge) {
      await app.supabase.from('drivers').update({ verification_badge: badge }).eq('id', driver.id)
    }

    const profileComplete = !!(driver.photo_url && driver.languages?.length && driver.home_base_city)

    return reply.send({
      success: true,
      data: {
        verification_badge: badge,
        checklist: {
          profile_complete: profileComplete,
          license_submitted: !!license,
          license_verified: license?.status === 'verified',
          vehicle_registered: vehicleList.length > 0,
          vehicle_verified: verifiedVehicles > 0,
          insurance_uploaded: (insuranceCount ?? 0) > 0,
          bank_linked: bankLinked,
        },
      },
    })
  })
}
