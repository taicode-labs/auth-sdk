import dayjs from 'dayjs'
import { enc } from 'crypto-js'
import {
  signToken,
  SignPayload,
  parseToken,
  verifyToken,
  isExpiredSignPayload,
  isValidSignPayload,
  SignSecret,
  isApiKey,
  API_KEY_PREFIX,
} from './index'

describe('@helper/token test', () => {
  it('signToken & parseToken & verifyToken should work', async () => {
    interface TestCase {
      input: {
        payload: SignPayload
        secret: SignSecret
      }
      output: {
        token: string
        expired: boolean
      }
    }

    const testCases: TestCase[] = []

    testCases.push({
      input: {
        payload: {
          // 写完整时间是为了避免发生时区转换导致输出不稳定的问题
          createdTime: dayjs('2020-12-31T16:00:00.000Z').toISOString(),
          expiredTime: dayjs('2020-12-31T16:00:00.000Z').toISOString(),
          data: {
            userId: 'test',
            username: 'test',
          }
        },
        secret: {
          secretKey: 'test',
          secretValue: 'test'
        },
      },
      output: {
        token: 'test:LiYiKKE_wahKBZGLWvUcQIKj5HC7WcBxqpuiGo5g330:eyJjcmVhdGVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiIsImRhdGEiOnsidXNlcklkIjoidGVzdCIsInVzZXJuYW1lIjoidGVzdCJ9LCJleHBpcmVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiJ9',
        expired: true,
      }
    })

    testCases.push({
      input: {
        payload: {
          // 写完整时间是为了避免发生时区转换导致输出不稳定的问题
          createdTime: dayjs('2020-12-31T16:00:00.000Z').toISOString(),
          expiredTime: dayjs('2020-12-31T16:00:00.000Z').toISOString(),
          data: {
            userId: 'test',
            username: 'test',
            other1: 'test',
            other2: 'test',
            other3: 'test',
          }
        },
        secret: {
          secretKey: 'test',
          secretValue: 'test'
        },
      },
      output: {
        token: 'test:fzl93RfPNekvCD_o7HLNo4lwVnYkJY6_K_o1lhGSCn0:eyJjcmVhdGVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiIsImRhdGEiOnsib3RoZXIxIjoidGVzdCIsIm90aGVyMiI6InRlc3QiLCJvdGhlcjMiOiJ0ZXN0IiwidXNlcklkIjoidGVzdCIsInVzZXJuYW1lIjoidGVzdCJ9LCJleHBpcmVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiJ9',
        expired: true,
      }
    })

    for (let index = 0; index < testCases.length; index++) {
      const testCase = testCases[index]
      const result = await signToken(testCase.input.secret, testCase.input.payload)
      expect(result).toEqual(testCase.output.token)

      const parseTokenResult = await parseToken(result)
      expect(parseTokenResult).toEqual({
        ...testCase.input.payload,
        secretKey: testCase.input.secret.secretKey,
      })

      const verifyTokenResult = await verifyToken(result, testCase.input.secret)
      expect(verifyTokenResult).toEqual(!testCase.output.expired)

      // 上述用例均为「已过期」token，结果为 false 无法区分「签名错误」与「已过期」。
      // 因此额外签一个未过期的等价 token，用来证明签名本身是有效的。
      const validToken = signToken(testCase.input.secret, {
        ...testCase.input.payload,
        expiredTime: dayjs().add(1, 'day').toISOString(),
      })
      expect(await verifyToken(validToken, testCase.input.secret)).toBe(true)
    }
  })

  /**
   * 回归测试：verifyToken 必须能真正校验签名。
   *
   * 背景：历史上 `verifyToken` 的签名比较被写反（`!==` 而非 `===`），
   * 且原有测试用例全部使用「已过期」的 token，断言结果恒为 false，
   * 导致该 bug 长期未被发现。以下用例用于防止回归。
   */
  describe('verifyToken 签名校验', () => {
    const secret: SignSecret = { secretKey: 'test-key', secretValue: 'test-value' }

    const payload: SignPayload = {
      createdTime: dayjs().toISOString(),
      expiredTime: dayjs().add(1, 'day').toISOString(),
      data: { userId: 'test', username: 'test' },
    }

    it('未过期且签名正确的 token 应当校验通过', async () => {
      const token = signToken(secret, payload)
      await expect(verifyToken(token, secret)).resolves.toBe(true)
    })

    it('签名被篡改的 token 应当校验失败', async () => {
      const token = signToken(secret, payload)
      const [secretKey, signString, base64DataString] = token.split(':')
      // 构造一个长度相同但内容不同的签名
      const tamperedSign = signString.slice(0, -1) + (signString.endsWith('A') ? 'B' : 'A')
      const tamperedToken = `${secretKey}:${tamperedSign}:${base64DataString}`
      await expect(verifyToken(tamperedToken, secret)).resolves.toBe(false)
    })

    it('载荷被篡改的 token 应当校验失败', async () => {
      const token = signToken(secret, payload)
      const [secretKey, signString] = token.split(':')
      const forgedPayload = enc.Base64url.stringify(
        enc.Utf8.parse(JSON.stringify({ ...payload, data: { userId: 'admin', username: 'admin' } }))
      )
      const tamperedToken = `${secretKey}:${signString}:${forgedPayload}`
      await expect(verifyToken(tamperedToken, secret)).resolves.toBe(false)
    })

    it('secretValue 不匹配的 token 应当校验失败', async () => {
      const token = signToken(secret, payload)
      await expect(verifyToken(token, { ...secret, secretValue: 'other-value' })).resolves.toBe(false)
    })

    it('secretKey 不匹配的 token 应当校验失败', async () => {
      const token = signToken(secret, payload)
      await expect(verifyToken(token, { ...secret, secretKey: 'other-key' })).resolves.toBe(false)
    })

    it('已过期的 token 应当校验失败', async () => {
      const expiredToken = signToken(secret, {
        ...payload,
        expiredTime: dayjs().subtract(1, 'day').toISOString(),
      })
      await expect(verifyToken(expiredToken, secret)).resolves.toBe(false)
    })
  })

  /**
   * 回归测试：isApiKey 的前缀必须与 account 签发的 API Key 前缀一致。
   *
   * 背景：历史上该函数使用 'API-KEY-'（大写 + 连字符），与实际格式
   * `apikey-{32位随机字符}`（小写、无连字符）不一致，导致：
   * 1. isApiKey 对真实 API Key 恒返回 false；
   * 2. verifyToken / parseToken 中针对 API Key 的提前返回成为死代码。
   */
  describe('isApiKey', () => {
    const secret: SignSecret = { secretKey: 'test-key', secretValue: 'test-value' }

    const payload: SignPayload = {
      createdTime: dayjs().toISOString(),
      expiredTime: dayjs().add(1, 'day').toISOString(),
      data: { userId: 'test', username: 'test' },
    }

    it('前缀应当是 apikey-', () => {
      expect(API_KEY_PREFIX).toBe('apikey-')
    })

    it('真实格式的 API Key 应当被识别', () => {
      expect(isApiKey(`apikey-${'A'.repeat(32)}`)).toBe(true)
    })

    it('大小写敏感：不符合前缀的字符串不应被识别', () => {
      expect(isApiKey(`API-KEY-${'A'.repeat(32)}`)).toBe(false)
      expect(isApiKey(`APIKEY-${'A'.repeat(32)}`)).toBe(false)
    })

    it('普通 token 不应被识别为 API Key', () => {
      expect(isApiKey(signToken(secret, payload))).toBe(false)
    })

    it('API Key 不能被当作 token 解析或校验', async () => {
      const apiKey = `apikey-${'A'.repeat(32)}`
      await expect(parseToken(apiKey)).resolves.toBe(null)
      await expect(verifyToken(apiKey, secret)).resolves.toBe(false)
    })
  })

  it('isExpiredToken should work', async () => {
    for (let index = 0; index < 10; index++) {

      const isExpired = Math.random() > 0.5

      const expiredTime = isExpired
        ? dayjs().subtract(1, 'day').toISOString()
        : dayjs().add(1, 'day').toISOString()

      const result = isExpiredSignPayload({
        expiredTime,
        createdTime: dayjs().toISOString(),
        data: {
          userId: 'test',
          username: 'test'
        }
      })

      expect(result).toEqual(isExpired)
    }
  })

  it('isValidPayload should work', async () => {
    const testCases: { input: unknown, output: boolean }[] = []

    testCases.push({
      input: {
        expiredTime: dayjs().toISOString(),
        createdTime: dayjs().toISOString(),
        data: {
          userId: 'test',
          username: 'test'
        }
      },
      output: true
    })

    testCases.push({
      input: {
        createdTime: dayjs().toISOString(),
        data: {
          userId: 'test',
          username: 'test'
        }
      },
      output: true
    })

    testCases.push({
      input: {
        createdTime: dayjs().toISOString(),
      },
      output: false
    })

    testCases.push({
      input: {
        expiredTime: dayjs().toISOString(),
        createdTime: dayjs().toISOString(),
        data: null
      },
      output: false
    })

    testCases.push({
      input: {
        expiredTime: dayjs().toISOString(),
        createdTime: dayjs().toISOString(),
        data: {
          userId: 'test',
          username: 'test',
          other: 'test2'
        }
      },
      output: true
    })

    for (let index = 0; index < testCases.length; index++) {
      const testCase = testCases[index]
      expect(isValidSignPayload(testCase.input)).toEqual(testCase.output)
    }
  })
})
