// Fastify route plugin exposing all KYC HTTP endpoints — validates request schemas and delegates to individual verification modules

import type { FastifyInstance, FastifyRequest } from 'fastify'
import fp from 'fastify-plugin'
import { authenticate } from '../lib/authenticate.js'
import { getCurrentLevel, getKYCRecord } from '../modules/kyc/repository.js'
import { KYCStatus, KYCLevel, UserRole, type KYCRequest, type KYCResult } from '../modules/kyc/types.js'

// Verification handlers — each module is fully independent
import { verifyPhone }     from '../modules/kyc/verifications/phone.js'
import { verifyEmail }     from '../modules/kyc/verifications/email.js'
import { verifyAadhaar }   from '../modules/kyc/verifications/aadhaar.js'
import { verifyPan }       from '../modules/kyc/verifications/pan.js'
import { verifyDl }        from '../modules/kyc/verifications/dl.js'
import { verifyRc }        from '../modules/kyc/verifications/rc.js'
import { verifyGst }       from '../modules/kyc/verifications/gst.js'
import { verifyFaceMatch } from '../modules/kyc/verifications/face-match.js'
import { verifyBank }      from '../modules/kyc/verifications/bank.js'

// ---------------------------------------------------------------------------
// Verification dispatch map
// ---------------------------------------------------------------------------

type VerifyFn = (req: KYCRequest) => Promise<KYCResult>

const VERIFIERS: Record<string, VerifyFn> = {
  phone:      verifyPhone,
  email:      verifyEmail,
  aadhaar:    verifyAadhaar,
  pan:        verifyPan,
  dl:         verifyDl,
  rc:         verifyRc,
  gst:        verifyGst,
  face_match: verifyFaceMatch,
  bank:       verifyBank,
}

// ---------------------------------------------------------------------------
// Request / response schemas (JSON Schema — Fastify uses ajv under the hood)
// ---------------------------------------------------------------------------

const verifyBodySchema = {
  type: 'object',
  required: ['user_id', 'role', 'metadata'],
  properties: {
    user_id:  { type: 'string' },
    role:     { type: 'string', enum: Object.values(UserRole) },
    metadata: { type: 'object', additionalProperties: true },
  },
} as const

const verifyParamsSchema = {
  type: 'object',
  required: ['type'],
  properties: {
    type: { type: 'string', enum: Object.keys(VERIFIERS) },
  },
} as const

const statusParamsSchema = {
  type: 'object',
  required: ['userId'],
  properties: {
    userId: { type: 'string' },
  },
} as const

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/**
 * POST /kyc/verify/:type
 * Dispatches to the correct verification module based on the :type param.
 *
 * TODO: call authenticate pre-handler
 * TODO: look up VERIFIERS[type], call with KYCRequest from body
 * TODO: call upsertVerification(supabase, user_id, type, result)
 * TODO: return 200 with KYCResult or 422 on validation failure
 */
async function handleVerify(
  this: FastifyInstance,
  request: FastifyRequest<{ Params: { type: string }; Body: KYCRequest }>,
  reply: FastifyReply,
): Promise<void> {
  const { type } = request.params
  void type
  // TODO: implement verify handler
  reply.code(501).send({ error: 'handleVerify: not implemented' })
}

/**
 * GET /kyc/status/:userId
 * Returns the current KYC level for a user.
 *
 * TODO: call authenticate pre-handler
 * TODO: assert that requester is the userId or has an admin role
 * TODO: call getCurrentLevel(supabase, userId), return { user_id, kyc_level }
 */
async function handleStatus(
  this: FastifyInstance,
  request: FastifyRequest<{ Params: { userId: string } }>,
  reply: FastifyReply,
): Promise<void> {
  const { userId } = request.params
  void userId
  void getKYCRecord
  void getCurrentLevel
  // TODO: implement status handler
  reply.code(501).send({ error: 'handleStatus: not implemented' })
}

// ---------------------------------------------------------------------------
// Plugin registration
// ---------------------------------------------------------------------------

export const kycRoutes = fp(async (app: FastifyInstance) => {
  app.post<{ Params: { type: string }; Body: KYCRequest }>(
    '/kyc/verify/:type',
    {
      preHandler: authenticate,
      schema: { params: verifyParamsSchema, body: verifyBodySchema },
    },
    handleVerify.bind(app),
  )

  app.get<{ Params: { userId: string } }>(
    '/kyc/status/:userId',
    {
      preHandler: authenticate,
      schema: { params: statusParamsSchema },
    },
    handleStatus.bind(app),
  )
})
