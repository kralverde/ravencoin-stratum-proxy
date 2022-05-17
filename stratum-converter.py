import asyncio
import json
import time
import sys

import base58
import sha3

from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCConnection, JSONRPCAutoDetect, Request, serve_rs, handler_invocation, RPCError
from functools import partial
from hashlib import sha256
from typing import Callable, Coroutine, Set, List, Optional

from main import TransactionState


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


    def build_block(self, nonce: str, mixHash: str) -> str:
        return state.header.hex() + nonce + mixHash + var_int(len(self.externalTxs) + 1).hex() + self.coinbase_tx.hex() + ''.join(self.externalTxs)

class StratumSession(RPCSession):

    def __init__(self, state: TransactionState, submit: Callable[[str], Coroutine], testnet: bool, transport):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        self._state: TransactionState = state
        self._submit = submit
        self._testnet = testnet
        self.handlers = {
            'mining.subscribe': self.handle_subscribe,
            'mining.authorize': self.handle_authorize,
            'mining.submit': self.handle_submit
        }

    async def handle_request(self, request):
        if isinstance(request, Request):
            handler = self.handlers.get(request.method, None)
        else:
            handler = None
        await handler_invocation(handler, request)()

    async def connection_lost(self):
        self._state.new_sessions.discard(self)
        self._state.all_sessions.discard(self)
        return await super().connection_lost()

    async def handle_subscribe(self, *args):
        # Dummy data
        self._state.new_sessions.add(self)
        return ['00'*4, 4]
    
    async def handle_authorize(self, username: str, password: str):
        address = username.split('.')
        if base58.b58decode_check(address)[0] != (111 if self._testnet else 60):
            raise RPCError(1, f'Invalid address {address}')
        if not self._state.address:
            self._state.address = address
        return True

    async def handle_submit(self, worker: str, job_id: str, nonce_hex: str, header_hex: str, mixhash_hex: str):
        if nonce_hex[:2].lower() == '0x':
            nonce_hex = nonce_hex[2:]
        if mixhash_hex[:2].lower() == '0x':
            mixhash_hex = mixhash_hex[2:]
        
        block_hex = self._state.build_block(nonce_hex, mixhash_hex)

        await self._submit(block_hex)
        return True

async def stateUpdater(state: TemplateState, node_url: str, node_username: str, node_password: str, node_port: int):
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

                if state.height == -1 or state.height != height_int:
                    # New block, update everything

                    state.target = target_hex
                    state.bits = bits_hex
                    state.version = version_int
                    state.prevHash = bytes.fromhex(prev_hash_hex)[::-1]

                    # Generate seed hash #
                    if state.height == - 1 or height_int > state.height:
                        if not state.seedHash:
                            seed_hash = bytes(32)
                            for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                k = sha3.keccak_256()
                                k.update(seed_hash)
                                seed_hash = k.digest()
                            state.seedHash = seed_hash
                        elif state.height % KAWPOW_EPOCH_LENGTH == 0:
                            # Hashing is expensive, so want use the old val
                            k = sha3.keccak_256()
                            k.update(state.seedHash)
                            seed_hash = k.digest()
                            state.seedHash = seed_hash
                    else:
                        # Maybe a chain reorg?
                        
                        # If the difference between heights is greater than how far we are into the epoch
                        if state.height % KAWPOW_EPOCH_LENGTH - (state.height - height_int) < 0:
                            # We must go back an epoch; recalc
                            seed_hash = bytes(32)
                            for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                k = sha3.keccak_256()
                                k.update(seed_hash)
                                seed_hash = k.digest()
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
                if state.height == -1 or state.height != height_int or len(state.externalTxs) != len(txs_list):
                                            # Create merkle & update txs
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

                    for session in state.all_sessions:
                        await session.send_notification('mining.notify', ('0', state.headerHash, state.seedHash.hex(), state.target, True, state.height, state.bits))
                

                for session in state.new_sessions:
                    state.all_sessions.add(session)
                    await session.send_notification('mining.set_target', (state.target,))
                    await session.send_notification('mining.notify', ('0', state.headerHash, state.seedHash.hex(), state.target, True, state.height, state.bits))
                state.new_sessions.clear()

            except Exception as e:
                print('Failed to query blocktemplate from node')
                import traceback
                traceback.print_exception(e)
                exit(1)

if __name__ == '__main__':

    if len(sys.argv) < 6:
        print('arguments must be: proxy_port, node_ip, node_username, node_password, node_port, (testnet - optional)')
        exit(0)

    proxy_port = int(sys.argv[1])
    node_ip = str(sys.argv[2])
    node_username = str(sys.argv[3])
    node_password = str(sys.argv[4])
    node_port = int(sys.argv[5])
    testnet = False
    if len(sys.argv) > 6:
        testnet = bool(sys.argv[6])

    print('Starting stratum converter')

    # The shared state
    state = TemplateState()

    async def submit(block_hex: str):
        data = {
            'jsonrpc':'2.0',
            'id':'0',
            'method':'submitblock',
            'params':[block_hex]
        }
        async with ClientSession() as session:
            async with session.post(f'http://{node_username}:{node_password}@{node_ip}:{node_port}', data=json.dumps(data)) as resp:
                json_resp = await resp.json()
                print(json_resp)
                if json_resp.get('error', None):
                    raise RPCError(1, json_resp['error'])
                if json_resp.get('result', None):
                    raise RPCError(1, json_resp['result'])

    session_generator = partial(StratumSession, state, submit, testnet)

    asyncio.create_task(serve_rs(session_generator, 'localhost', proxy_port, reuse_address=True))

    async def updateState():
        while True:
            await stateUpdater(state, node_ip, node_username, node_password, node_port)
            await asyncio.sleep(0.1)

    asyncio.run(updateState())