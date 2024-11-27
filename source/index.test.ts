import dayjs from 'dayjs'
import { signToken, SignPayload, parseToken, verifyToken, isExpiredToken, isValidPayload } from './index'

describe('@helper/token test', () => {
  it('signToken & parseToken & verifyToken should work', async () => {
    interface TestCase {
      input: {
        payload: SignPayload
        secret: [string, string]
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
        secret: ['test', 'test'],
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
        secret: ['test', 'test'],
      },
      output: {
        token: 'test:fzl93RfPNekvCD_o7HLNo4lwVnYkJY6_K_o1lhGSCn0:eyJjcmVhdGVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiIsImRhdGEiOnsib3RoZXIxIjoidGVzdCIsIm90aGVyMiI6InRlc3QiLCJvdGhlcjMiOiJ0ZXN0IiwidXNlcklkIjoidGVzdCIsInVzZXJuYW1lIjoidGVzdCJ9LCJleHBpcmVkVGltZSI6IjIwMjAtMTItMzFUMTY6MDA6MDAuMDAwWiJ9',
        expired: true,
      }
    })

    for (let index = 0; index < testCases.length; index++) {
      const testCase = testCases[index]
      const result = await signToken(testCase.input.secret[0], testCase.input.secret[1], testCase.input.payload)
      expect(result).toEqual(testCase.output.token)

      const parseTokenResult = await parseToken(result)
      expect(parseTokenResult).toEqual(testCase.input.payload)

      const verifyTokenResult = await verifyToken(result, testCase.input.secret[1])
      expect(verifyTokenResult).toEqual(!testCase.output.expired)
    }
  })

  it('isExpiredToken should work', async () => {
    for (let index = 0; index < 10; index++) {

      const isExpired = Math.random() > 0.5

      const expiredTime = isExpired
        ? dayjs().subtract(1, 'day').toISOString()
        : dayjs().add(1, 'day').toISOString()

      const result = isExpiredToken({
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
        data: {}
      },
      output: false
    })
    
    testCases.push({
      input: {
        expiredTime: dayjs().toISOString(),
        createdTime: dayjs().toISOString(),
        data: {
          userId: 'test'
        }
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
      expect(isValidPayload(testCase.input)).toEqual(testCase.output)
    }
  })
})
