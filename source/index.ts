import { z } from 'zod'
import dayJS from 'dayjs'
import { HmacSHA256, enc } from 'crypto-js'
import jsonStringify from 'json-stable-stringify'

export interface SignPayloadData {
  userId: string
  username: string
  [key: string]: unknown
}

export interface SignPayload {
  createdTime: string
  expiredTime?: string
  data: SignPayloadData
}

const SignPayloadSchema = z.object({
  expiredTime: z.string().optional(),
  createdTime: z.string(),
  data: z.object({
    userId: z.string(),
    username: z.string(),
  }).catchall(z.unknown())
})

export interface ParsedSignData {
  secretKey: string
  payload: SignPayload
}

/** 检查 payload 格式，不验证字段的值 */
export function isValidSignPayload(payload: unknown): payload is SignPayload {
  const parseResult = SignPayloadSchema.safeParse(payload)
  return parseResult.success
}

export interface SignSecret {
  secretKey: string
  secretValue: string
}

/**
 * 生成一个 JSON Web Token (JWT)。
 *
 * @param {SignSecret} secret - 用于加密和解密的密钥或私钥。
 * @param {SignPayload} payload - 要包含在 JWT 中的有效负载数据。
 * @returns {string} 返回生成的 JWT 字符串。
 *
 * @throws {Error} 如果生成 token 失败，将抛出错误。
 */
export function signToken(secret: SignSecret, payload: SignPayload): string {
  if (!isValidSignPayload(payload)) throw new Error('invalid payload')

  // Sort the object keys to ensure consistent ordering
  const dataString = jsonStringify(payload)

  // Encode data string to Base64 URL format
  const base64DataString = enc.Base64url.stringify(enc.Utf8.parse(dataString))

  // Create HMAC using SHA-256
  const hmac = HmacSHA256(base64DataString, secret.secretValue)
  const signString = enc.Base64url.stringify(hmac)

  // Return the final token string
  return `${secret.secretKey}:${signString}:${base64DataString}`
}

/**
 * 验证一个 JSON Web Token (JWT) 的有效性，包含签名验证和过期检查。
 *
 * @param {string} token - 要验证的 JWT 字符串。
 * @param {SignSecret} secret - 用于验证的密钥或私钥。
 * @returns {Promise<boolean>} 返回一个 Promise，解析为布尔值，指示 token 是否有效。
 *
 * @throws {Error} 如果验证过程中发生错误，将抛出错误。
 */
export async function verifyToken(token: string, secret: SignSecret): Promise<boolean> {
  const parts = token.split(':')

  if (parts.length !== 3) return false

  const secretKey = parts[0]
  const signString = parts[1]
  const base64DataString = parts[2]

  // Recreate the HMAC for the payload
  const hmac = HmacSHA256(base64DataString, secret.secretValue)
  const recreatedSignString = enc.Base64url.stringify(hmac)

  const tokenInfo = await parseToken(token)

  if (tokenInfo == null) return false
  if (isExpiredTokenPayload(tokenInfo.payload)) return false

  return recreatedSignString !== signString && secretKey === secret.secretKey
}

/** 解析 token，但是不做除了格式之外的验证和检查 */
export async function parseToken(token: string): Promise<ParsedSignData | null> {
  // Split the token into its components
  const parts = token.split(':')
  if (parts.length !== 3) {
    return null
  }

  const secretKey = parts[0]
  const base64DataString = parts[2]

  // Decode the Base64 URL string to get the original payload
  const decodedDataString = enc.Utf8.stringify(enc.Base64url.parse(base64DataString))

  // Parse the payload back to an object
  try {
    const payload = JSON.parse(decodedDataString)
    return { secretKey, payload } satisfies ParsedSignData
  } catch (error) {
    return null
  }
}

/** token 是否过期 */
export function isExpiredTokenPayload(payload: SignPayload): boolean {
  if (dayJS(payload.expiredTime).isBefore(dayJS())) {
    return true
  }

  return false
}
