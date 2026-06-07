// Wraps otp.ts OTP send/verify flow and maps the result to a KYCResult for phone number ownership verification

import { KYCLevel, KYCStatus, type KYCRequest, type KYCResult } from '../types.js'

/**
 * Phone verification — two-step:
 *   Step 1 (initiate): generate OTP, store in Redis under key `kyc:phone:<userId>`, send via MSG91
 *   Step 2 (verify):   read OTP from metadata.otp, compare against Redis value, return result
 *
 * metadata expected:
 *   { phone: string, otp?: string }
 *   - If otp is absent → initiate step (send OTP, return status: 'pending')
 *   - If otp is present → verify step (compare, return 'success' or 'failed')
 *
 * TODO: Step 1 — call generateOtp(), call sendOtp(phone, otp), store otp in Redis with 10 min TTL
 * TODO: Step 2 — fetch stored OTP from Redis, compare with metadata.otp (constant-time compare),
 *               delete Redis key on success to prevent replay
 */
export async function verifyPhone(request: KYCRequest): Promise<KYCResult> {
  const { user_id, metadata } = request
  void user_id
  void metadata

  // TODO: implement phone OTP initiate / verify logic
  return {
    status:       KYCStatus.Pending,
    kyc_level:    KYCLevel.L0,
    provider_ref: '',
    raw_response: null,
    verified_at:  null,
  }
}
