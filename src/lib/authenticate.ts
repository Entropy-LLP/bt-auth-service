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

export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    reply.code(401).send({ success: false, error: 'Authorization header required' })
    return
  }

  const token = header.slice(7)
  let payload: JwtPayload

  try {
    payload = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload
  } catch {
    reply.code(401).send({ success: false, error: 'Invalid or expired token' })
    return
  }

  if (!payload.userId || !payload.role) {
    reply.code(401).send({ success: false, error: 'Token missing required claims' })
    return
  }

  request.user = { userId: payload.userId, role: payload.role }
}
