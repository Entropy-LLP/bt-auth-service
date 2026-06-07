import 'dotenv/config'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import { supabasePlugin } from './plugins/supabase.js'
import { redisPlugin } from './plugins/redis.js'
import { authRoutes } from './routes/auth.js'
import { onboardingRoutes } from './routes/onboarding.js'
import { kycRoutes } from './routes/kyc.js'

const app = Fastify({
  logger: {
    transport: process.env.NODE_ENV === 'development'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
  },
})

async function bootstrap() {
  await app.register(cors, { origin: true })
  await app.register(supabasePlugin)
  await app.register(redisPlugin)
  await app.register(authRoutes, { prefix: '/auth' })
  await app.register(onboardingRoutes, { prefix: '/onboarding' })
  await app.register(kycRoutes, { prefix: '/kyc' })
  app.get('/health', () => ({ status: 'ok', service: 'bt-auth-service', ts: new Date().toISOString() }))
  await app.listen({ port: Number(process.env.PORT ?? 3001), host: '0.0.0.0' })
}

bootstrap().catch(err => { console.error(err); process.exit(1) })
