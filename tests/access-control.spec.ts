import { Config } from '@algorandfoundation/algokit-utils'
import { algorandFixture } from '@algorandfoundation/algokit-utils/testing'
import { TransactionSignerAccount } from '@algorandfoundation/algokit-utils/types/account'
import { Account, bytesToBase64 } from 'algosdk'
import { AccessControlFactory } from '../smart_contracts/artifacts/access_control/AccessControlClient'

describe('access control contract', () => {
  const localnet = algorandFixture()
  beforeAll(() => {
    Config.configure({
      debug: true,
      // traceAll: true,
    })
  })
  beforeEach(localnet.newScope)

  const deploy = async (account: Account & TransactionSignerAccount) => {
    const factory = localnet.algorand.client.getTypedAppFactory(AccessControlFactory, {
      defaultSender: account.addr,
    })

    const { appClient } = await factory.deploy({ onUpdate: 'append', onSchemaBreak: 'append' })
    return { client: appClient }
  }

  test('get default admin role', async () => {
    const { testAccount } = localnet.context
    const { client } = await deploy(testAccount)

    const result = await client.send.defaultAdminRole()
    const expected = bytesToBase64(new Uint8Array(32).fill(0))

    expect(bytesToBase64(result.return!)).toEqual(expected)
  })
})
