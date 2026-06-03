import type { FastifyRequest, FastifyReply } from 'fastify'
import jwt from 'jsonwebtoken'

export type JwtPayload = {
  userId: string
  role: string
}

declare module 'fastify' {
  interface FastifyRequest {
    user: JwtPayload
  }
}

interface SupabaseJwtPayload extends jwt.JwtPayload {
  sub: string
  user_metadata?: Record<string, unknown>
  app_metadata?: Record<string, unknown>
}

export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    reply.code(401).send({ success: false, error: 'Authorization header required' })
    return
  }

  const token = header.slice(7)
  let payload: SupabaseJwtPayload

  try {
    payload = jwt.verify(token, process.env.SUPABASE_JWT_SECRET!) as SupabaseJwtPayload
  } catch {
    reply.code(401).send({ success: false, error: 'Invalid or expired token' })
    return
  }

  if (!payload.sub) {
    reply.code(401).send({ success: false, error: 'Token missing sub claim' })
    return
  }

  const { data: user, error } = await request.server.supabase
    .from('users')
    .select('id, role')
    .eq('auth_id', payload.sub)
    .maybeSingle()

  if (error || !user) {
    reply.code(401).send({ success: false, error: 'User not found' })
    return
  }

  request.user = { userId: user.id, role: user.role }
}
