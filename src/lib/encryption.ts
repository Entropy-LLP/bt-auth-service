import crypto from 'crypto'

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12

let _key: Buffer | null = null

function getKey(): Buffer {
  if (_key) return _key
  const raw = process.env.ENCRYPTION_KEY
  if (!raw || raw.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be set to a 64-char hex string (32 bytes)')
  }
  _key = Buffer.from(raw, 'hex')
  return _key
}

// format: <iv_hex>:<authTag_hex>:<ciphertext_hex>
export function encrypt(text: string): string {
  const key = getKey()
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`
}

export function decrypt(ciphertext: string): string {
  const key = getKey()
  const parts = ciphertext.split(':')
  if (parts.length !== 3) throw new Error('Invalid ciphertext format')
  const iv = Buffer.from(parts[0], 'hex')
  const tag = Buffer.from(parts[1], 'hex')
  const encrypted = Buffer.from(parts[2], 'hex')
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
  decipher.setAuthTag(tag)
  return decipher.update(encrypted) + decipher.final('utf8')
}

export function hashForLookup(text: string): string {
  return crypto.createHash('sha256').update(text.trim().toLowerCase()).digest('hex')
}
