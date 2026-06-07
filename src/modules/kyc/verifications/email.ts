// Email OTP or magic-link verification flow, returns KYCResult confirming email ownership

import { KYCLevel, KYCStatus, type KYCRequest, type KYCResult } from '../types.js'

/**
 * Email verification — two-step:
 *   Step 1 (initiate): generate 6-digit OTP, store in Redis under `kyc:email:<userId>` with 15 min TTL,
 *                      send via transactional email provider (SendGrid / AWS SES — TBD)
 *   Step 2 (verify):   compare metadata.otp against Redis value, return result
 *
 * metadata expected:
 *   { email: string, otp?: string }
 *
 * TODO: Step 1 — call generateOtp(), send email with OTP (provider TBD), store in Redis
 * TODO: Step 2 — fetch from Redis, compare, delete on match, return KYCResult
 * TODO: consider magic-link alternative (JWT signed link with 15 min expiry) as a future option
 */
export async function verifyEmail(request: KYCRequest): Promise<KYCResult> {
  const { user_id, metadata } = request
  void user_id
  void metadata

  // TODO: implement email OTP initiate / verify logic
  return {
    status:       KYCStatus.Pending,
    kyc_level:    KYCLevel.L0,
    provider_ref: '',
    raw_response: null,
    verified_at:  null,
  }
}
