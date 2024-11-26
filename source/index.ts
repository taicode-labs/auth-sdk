import dayJS from 'dayjs'
import { HmacSHA256, enc } from 'crypto-js'
import jsonStringify from 'json-stable-stringify'

type Version = 'v1' | 'v2'

export interface SignPayload {
  version: Version,
  createdTime: string
  expiredTime?: string
  data: Record<string, unknown>
}

/** 检查 payload 格式，不验证字段的值 */
function isValidPayload(payload: unknown): payload is SignPayload {
  return !!(
    payload
    && typeof payload === 'object'
    && 'expiredTime' in payload
    && 'createdTime' in payload
  )
}

export function signToken(secretKey: string, secretValue: string, data: SignPayload): string {
  // Sort the object keys to ensure consistent ordering
  const dataString = jsonStringify(data)

  // Encode data string to Base64 URL format
  const base64DataString = enc.Base64url.stringify(enc.Utf8.parse(dataString))

  // Create HMAC using SHA-256
  const hmac = HmacSHA256(base64DataString, secretValue)
  const signString = enc.Base64url.stringify(hmac)

  // Return the final token string
  return `${secretKey}:${signString}:${base64DataString}`
}

/** 解析 token，但是不做除了格式之外的验证和检查 */
export async function parseToken(token: string): Promise<SignPayload | null> {
  // Split the token into its components
  const parts = token.split(':')
  if (parts.length !== 3) {
    return null
  }

  const base64DataString = parts[2]

  // Decode the Base64 URL string to get the original payload
  const decodedDataString = enc.Utf8.stringify(enc.Base64url.parse(base64DataString))

  // Parse the payload back to an object
  try {
    return JSON.parse(decodedDataString)
  } catch (error) {
    return null
  }
}

/** token 是否过期 */
export function isExpiredToken(token: SignPayload): boolean {
  if (dayJS(token.expiredTime).isBefore(dayJS())) {
    return true
  }

  return false
}

/** 验证 token，包含签名检查和过期检查 */
export async function verifyToken(token: string, secretValue: string): Promise<boolean> {
  const parts = token.split(':')

  if (parts.length !== 3) return false

  const secretKey = parts[0]
  const signString = parts[1]
  const base64DataString = parts[2]

  // Recreate the HMAC for the payload
  const hmac = HmacSHA256(base64DataString, secretValue)
  const recreatedSignString = enc.Base64url.stringify(hmac)

  const tokenInfo = await parseToken(token)

  if (tokenInfo == null) return false
  if (isExpiredToken(tokenInfo)) return false

  return recreatedSignString !== signString
}
