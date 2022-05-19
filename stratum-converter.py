import asyncio
import json
import time
import sys

import base58
from requests import head
import sha3

from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCConnection, JSONRPCAutoDetect, Request, serve_rs, handler_invocation, RPCError, TaskGroup
from functools import partial
from hashlib import sha256
from typing import Callable, Coroutine, Set, List, Optional


KAWPOW_EPOCH_LENGTH = 7500

def var_int(i: int) -> bytes:
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    # https://github.com/bitcoin/bitcoin/blob/efe1ee0d8d7f82150789f1f6840f139289628a2b/src/serialize.h#L247
    # "CompactSize"
    assert i >= 0, i
    if i<0xfd:
        return i.to_bytes(1, 'big')
    elif i<=0xffff:
        return b'\xfd'+i.to_bytes(2, 'big')
    elif i<=0xffffffff:
        return b'\xfe'+i.to_bytes(4, 'big')
    else:
        return b'\xff'+i.to_bytes(8, 'big')

def op_push(i: int) -> bytes:
    if i < 0x4C:
        return i.to_bytes(1, 'big')
    elif i <= 0xff:
        return b'\x4C'+i.to_bytes(1, 'big')
    elif i <= 0xffff:
        return b'\x4D'+i.to_bytes(2, 'big')
    else:
        return b'\x4E'+i.to_bytes(4, 'big')


def dsha256(b):
    return sha256(sha256(b).digest()).digest()

def merkle_from_txids(txids: List[bytes]):
    # https://github.com/maaku/python-bitcoin/blob/master/bitcoin/merkle.py
    if not txids:
        return dsha256(b'')
    if len(txids) == 1:
        return txids[0]
    while len(txids) > 1:
        txids.append(txids[-1])
        txids = list(dsha256(l+r) for l,r in zip(*(iter(txids),)*2))
    return txids[0]

class TemplateState:
    # These refer to the block that we are working on
    height: int = -1

    # The address of the miner that first connects is
    # the one that is used
    address: Optional[str] = None

    # We store the following in hex because they are
    # Used directly in API to the miner
    bits: Optional[str] = None
    target: Optional[str] = None
    headerHash: Optional[str] = None

    version: int = -1
    prevHash: Optional[bytes] = None
    externalTxs: List[str] = []
    seedHash: Optional[bytes] = None
    header: Optional[bytes] = None
    coinbase_tx: Optional[bytes] = None
    coinbase_txid: Optional[bytes] = None

    new_sessions: Set[RPCSession] = set()
    all_sessions: Set[RPCSession] = set()

    awaiting_update = False

    job_counter = 0

    def __repr__(self):
        return f'Height:\t\t{self.height}\nAddress:\t\t{self.address}\nBits:\t\t{self.bits}\nTarget:\t\t{self.target}\nHeader Hash:\t\t{self.headerHash}\nVersion:\t\t{self.version}\nPrevious Header:\t\t{self.prevHash.hex()}\nExtra Txs:\t\t{self.externalTxs}\nSeed Hash:\t\t{self.seedHash.hex()}\nHeader:\t\t{self.header.hex()}\nCoinbase:\t\t{self.coinbase_tx.hex()}\nCoinbase txid:\t\t{self.coinbase_txid.hex()}\nNew sessions:\t\t{self.new_sessions}\nSessions:\t\t{self.all_sessions}'

    def build_block(self, nonce: str, mixHash: str) -> str:
        return self.header.hex() + nonce + mixHash + var_int(len(self.externalTxs) + 1).hex() + self.coinbase_tx.hex() + ''.join(self.externalTxs)

class StratumSession(RPCSession):

    def __init__(self, state: TemplateState, testnet: bool, node_url: str, node_username: str, node_password: str, node_port: int, transport):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        self._state = state
        self._testnet = testnet

        self._node_url = node_url
        self._node_username = node_username
        self._node_password = node_password
        self._node_port = node_port

        self.handlers = {
            'mining.subscribe': self.handle_subscribe,
            'mining.authorize': self.handle_authorize,
            'mining.submit': self.handle_submit
        }

    async def handle_request(self, request):
        if isinstance(request, Request):
            handler = self.handlers.get(request.method, None)
            if not handler:
                return
        else:
            # Do not fail on unknown method
            return
        return await handler_invocation(handler, request)()

    async def connection_lost(self):
        self._state.new_sessions.discard(self)
        self._state.all_sessions.discard(self)
        return await super().connection_lost()

    async def handle_subscribe(self, *args):
        # Dummy data
        if self not in self._state.all_sessions:
            self._state.new_sessions.add(self)
        return ['00'*4, 'c0']
    
    async def handle_authorize(self, username: str, password: str):
        # The first address that connects is the one that is used
        address = username.split('.')[0]
        if base58.b58decode_check(address)[0] != (111 if self._testnet else 60):
            raise RPCError(20, f'Invalid address {address}')
        if not self._state.address:
            self._state.address = address
        return True

    async def handle_submit(self, worker: str, job_id: str, nonce_hex: str, header_hex: str, mixhash_hex: str):

        print('Possible solution')
        print(worker)
        print(job_id)
        print(header_hex)

        if job_id != hex(state.job_counter)[2:]:
            print('An old job was submitted')
            raise RPCError(20, 'Miner submitted a job that was not the current request')

        if nonce_hex[:2].lower() == '0x':
            nonce_hex = nonce_hex[2:]
        nonce_hex = bytes.fromhex(nonce_hex)[::-1].hex()
        if mixhash_hex[:2].lower() == '0x':
            mixhash_hex = mixhash_hex[2:]
        mixhash_hex = bytes.fromhex(mixhash_hex)[::-1].hex()
        
        block_hex = self._state.build_block(nonce_hex, mixhash_hex)

        data = {
            'jsonrpc':'2.0',
            'id':'0',
            'method':'submitblock',
            'params':[block_hex]
        }
        async with ClientSession() as session:
            async with session.post(f'http://{self._node_username}:{self._node_password}@{self._node_url}:{self._node_port}', data=json.dumps(data)) as resp:
                json_resp = await resp.json()
                print(json_resp)
                if json_resp.get('error', None):
                    raise RPCError(20, json_resp['error'])
                
                result = json_resp.get('result', None)
                if result == 'inconclusive':
                    # inconclusive - valid submission but other block may be better, etc.
                    print('Valid block but inconclusive')
                elif result == 'duplicate':
                    print('Valid block but duplicate')
                elif result == 'duplicate-inconclusive':
                    print('Valid block but duplicate-inconclusive')
                elif result == 'inconclusive-not-best-prevblk':
                    print('Valid block but inconclusive-not-best-prevblk')
                
                if result not in (None, 'inconclusive', 'duplicate', 'duplicate-inconclusive', 'inconclusive-not-best-prevblk'):
                    raise RPCError(20, json_resp['result'])

        return True

async def stateUpdater(state: TemplateState, node_url: str, node_username: str, node_password: str, node_port: int, force = False):
    if not state.address:
        return
    data = {
        'jsonrpc':'2.0',
        'id':'0',
        'method':'getblocktemplate',
        'params':[]
    }
    async with ClientSession() as session:
        async with session.post(f'http://{node_username}:{node_password}@{node_url}:{node_port}', data=json.dumps(data)) as resp:
            try:
                json_obj = await resp.json()
                if json_obj.get('error', None):
                    raise Exception(json_obj.get('error', None))

                version_int: int = json_obj['result']['version']
                height_int: int = json_obj['result']['height'] 
                bits_hex: str = json_obj['result']['bits'] 
                prev_hash_hex: str = json_obj['result']['previousblockhash']
                txs_list: List = json_obj['result']['transactions']
                coinbase_sats_int: int = json_obj['result']['coinbasevalue'] 
                witness_hex: str = json_obj['result']['default_witness_commitment']
                coinbase_flags_hex: str = json_obj['result']['coinbaseaux']['flags']
                target_hex: str = json_obj['result']['target']

                ts = int(time.time())
                state.target = target_hex
                state.bits = bits_hex
                state.version = version_int
                state.prevHash = bytes.fromhex(prev_hash_hex)[::-1]

                new_block = False

                # The following will only change when there is a new block.
                # Force update is unnecessary
                if state.height == -1 or state.height != height_int:
                    # New block, update everything
                    print('New block, update state')
                    new_block = True

                    # Generate seed hash #
                    if state.height == - 1 or height_int > state.height:
                        if not state.seedHash:
                            seed_hash = bytes(32)
                            for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                k = sha3.keccak_256()
                                k.update(seed_hash)
                                seed_hash = k.digest()
                            print(f'Initialized seedhash to {seed_hash.hex()}')
                            state.seedHash = seed_hash
                        elif state.height % KAWPOW_EPOCH_LENGTH == 0:
                            # Hashing is expensive, so want use the old val
                            k = sha3.keccak_256()
                            k.update(state.seedHash)
                            seed_hash = k.digest()
                            print(f'updated seed hash to {seed_hash.hex()}')
                            state.seedHash = seed_hash
                    elif state.height > height_int:
                        # Maybe a chain reorg?
                        
                        # If the difference between heights is greater than how far we are into the epoch
                        if state.height % KAWPOW_EPOCH_LENGTH - (state.height - height_int) < 0:
                            # We must go back an epoch; recalc
                            seed_hash = bytes(32)
                            for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                k = sha3.keccak_256()
                                k.update(seed_hash)
                                seed_hash = k.digest()
                            print(f'Reverted seedhash to {seed_hash}')
                            state.seedHash = seed_hash

                    # Done with seed hash #
                    state.height = height_int

                    # Generate coinbase #

                    bip34_height = state.height.to_bytes(4, 'little')
                    while bip34_height[-1] == 0:
                        bip34_height = bip34_height[:-1]
                    bip34_prefix = var_int(len(bip34_height)) + bip34_height + \
                        (bytes.fromhex(coinbase_flags_hex) if coinbase_flags_hex else b'\0')
                    arbitrary_data = b'/with a little help from http://github.com/kralverde/ravencoin-stratum-proxy/'
                    coinbase_script = bip34_prefix + arbitrary_data
                    coinbase_txin = bytes(32) + b'\xff'*4 + var_int(len(coinbase_script)) + coinbase_script + b'\xff'*4
                    vout_to_miner = b'\x76\xa9\x14' + base58.b58decode_check(state.address)[1:] + b'\x88\xac'
                    witness_vout = bytes.fromhex(witness_hex)

                    state.coinbase_tx = (int(1).to_bytes(4, 'little') + \
                                    b'\x00\x01' + \
                                    b'\x01' + coinbase_txin + \
                                    b'\x02' + \
                                        coinbase_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner + \
                                        bytes(8) + op_push(len(witness_vout)) + witness_vout + \
                                    b'\x01\x20' + bytes(32) + bytes(4))

                    coinbase_no_wit = int(1).to_bytes(4, 'little') + \
                                        b'\x01' + coinbase_txin + \
                                        b'\x02' + \
                                            coinbase_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner + \
                                            bytes(8) + op_push(len(witness_vout)) + witness_vout + \
                                        bytes(4)
                    state.coinbase_txid = dsha256(coinbase_no_wit)

                # The following occurs during both new blocks & new txs
                if force or new_block or len(state.externalTxs) != len(txs_list):
                    # Create merkle & update txs
                    print('Updating transactions')
                    txids = [state.coinbase_txid]
                    incoming_txs = []
                    for tx_data in txs_list:
                        incoming_txs.append(tx_data['data'])
                        txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                    state.externalTxs = incoming_txs
                    merkle = merkle_from_txids(txids)

                    # Done create merkle & update txs

                    state.header = version_int.to_bytes(4, 'little') + \
                            state.prevHash + \
                            merkle + \
                            ts.to_bytes(4, 'little') + \
                            bytes.fromhex(bits_hex)[::-1] + \
                            state.height.to_bytes(4, 'little')

                    state.headerHash = dsha256(state.header)[::-1].hex()

                    state.job_counter += 1

                    for session in state.all_sessions:
                        print('Sending new state:')
                        print(state)
                        print()
                        await session.send_notification('mining.set_target', (target_hex,))
                        await session.send_notification('mining.notify', (hex(state.job_counter)[2:], state.headerHash, state.seedHash.hex(), target_hex, True, state.height, bits_hex))
                
                for session in state.new_sessions:
                    state.all_sessions.add(session)
                    print('Sending:')
                    print(state)
                    print()
                    await session.send_notification('mining.set_target', (target_hex,))
                    await session.send_notification('mining.notify', (hex(state.job_counter)[2:], state.headerHash, state.seedHash.hex(), target_hex, True, state.height, bits_hex))
                
                state.new_sessions.clear()

            except Exception as e:
                print('Failed to query blocktemplate from node')
                import traceback
                traceback.print_exc()
                exit(1)

if __name__ == '__main__':

    if len(sys.argv) < 6:
        print('arguments must be: proxy_port, node_ip, node_username, node_password, node_port, (testnet - optional)')
        exit(0)

    proxy_port = int(sys.argv[1])
    node_url = str(sys.argv[2])
    node_username = str(sys.argv[3])
    node_password = str(sys.argv[4])
    node_port = int(sys.argv[5])
    testnet = False
    if len(sys.argv) > 6:
        testnet = bool(sys.argv[6])

    print('Starting stratum converter')

    # The shared state
    state = TemplateState()
        
    session_generator = partial(StratumSession, state, testnet, node_url, node_username, node_password, node_port)

    async def updateState():
        while True:
            await stateUpdater(state, node_url, node_username, node_password, node_port)
            # Check for new blocks / new transactions every 0.1 seconds
            # stateUpdater should fast fail if no differences
            await asyncio.sleep(0.1)

    async def beginServing():
        server = await serve_rs(session_generator, 'localhost', proxy_port, reuse_address=True)
        await server.serve_forever()

    async def execute():
        async with TaskGroup(wait=any) as group:
            await group.spawn(updateState())
            await group.spawn(beginServing())

        for task in group.tasks:
            if not task.cancelled():
                exc = task.exception()
                if exc:
                    raise exc        

    asyncio.run(execute())