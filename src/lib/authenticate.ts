import type { FastifyRequest, FastifyReply } from 'fastify'
import { verifyAccessToken, type JwtPayload } from './jwt.js'

declare module 'fastify' {
  interface FastifyRequest {
    user: JwtPayload
  }
}

export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    reply.code(401).send({ success: false, error: 'Authorization header required' })
    return
  }

  const token = header.slice(7)
  try {
    request.user = verifyAccessToken(token)
  } catch {
    reply.code(401).send({ success: false, error: 'Invalid or expired token' })
  }
}
