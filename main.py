import asyncio
from hashlib import sha256
from os import urandom
import sys
import time
import sha3
from functools import partial
import base58
import json
from typing import List, Tuple
from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCAutoDetect, JSONRPCConnection, serve_rs, handler_invocation, RPCError, TaskGroup
from aiorpcx.jsonrpc import Request

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
    while len(txids) > 1:
        txids.append(txids[-1])
        txids = list(dsha256(l+r) for l,r in zip(*(iter(txids),)*2))
    return txids[0]

class TransactionState:
    coinbase = None
    transport = None
    transactions = []
    update_coinbase_every = 10 * 60 * 10
    update_counter = update_coinbase_every
    my_address = None
    merkle = None
    header_hash = None
    seed_hash = None
    last_ts = None
    partial_header = None

    def partial_block(self) -> Tuple[bytes, bytes]:
        return bytes(reversed(self.partial_header)), var_int(len(self.transactions)) + b''.join(self.transactions)

    def build_coinbase_transaction(self, my_address: str, my_sats: int, witness_commitment: bytes):
        arbitrary_data = 'converted with the help of https://github.com/kralverde/ravencoin-stratum-proxy and nonce: '.encode('utf8') + urandom(0x10)
        coinbase_txin = bytes(32) + b'\xff\xff\xff\xff' + var_int(len(arbitrary_data)) + arbitrary_data + b'\xff\xff\xff\xff'
        vout1 = b'\x76\xa9\x14' + base58.b58decode(my_address)[1:] + b'\x88\xac'
        self.coinbase = int(1).to_bytes(4, 'little') + \
                        b'\x00\x01' + \
                        b'\x01' + coinbase_txin + \
                        b'\x02' + \
                            my_sats.to_bytes(8, 'little') + op_push(len(vout1)) + vout1 + \
                            bytes(8) + op_push(len(witness_commitment)) + witness_commitment + \
                        b'\x01\x20' + bytes(32) + bytes(4)

    def update_transactions(self, version:int, height:int, bits:bytes, ts:int, prev_hash:bytes, incoming_transactions, my_sats, witness_commitment):
        
        # Lock in the funny numbers
        if str(ts)[-3] == '4':
            ts = int(str(ts)[:-2]+'20')
        if str(ts)[-2] == '6':
            ts = int(str(ts)[:-1]+'9')
        
        # Hold on to the funny numbers
        if str(self.last_ts).endswith(('420', '69')):
            if ts > self.last_ts + 60 * 5:
                self.last_ts = ts
        else:
            self.last_ts = ts

        self.update_counter += 1
        changed_mine = False
        if self.my_address and self.update_counter >= self.update_coinbase_every:
            self.update_counter = 0
            changed_mine = True
            self.build_coinbase_transaction(self.my_address, my_sats, witness_commitment)
        if self.my_address and (changed_mine or len(self.transactions) != (len(incoming_transactions) + 1)):
            # recalculate everything
            new_transactions = [self.coinbase]
            transaction_ids = [bytes(reversed(dsha256(self.coinbase)))]
            for tx_data in incoming_transactions:
                raw_tx_hex = tx_data['data']
                tx_hash = tx_data['txid']
                new_transactions.append(bytes.fromhex(raw_tx_hex))
                transaction_ids.append(bytes(reversed(bytes.fromhex(tx_hash))))
            self.transactions = new_transactions
            self.merkle = merkle_from_txids(transaction_ids)
            
            self.partial_header = height.to_bytes(4, 'big') + \
                                    bits + \
                                    self.last_ts.to_bytes(4, 'big') + \
                                    bytes(reversed(self.merkle)) + \
                                    prev_hash + \
                                    version.to_bytes(4, 'big')
            
            self.header_hash = bytes(reversed(dsha256(bytes(reversed(self.partial_header)))))
            self.seed_hash = bytes(32)
            for _ in range(height//KAWPOW_EPOCH_LENGTH):
                k = sha3.keccak_256()
                k.update(self.seed_hash)
                self.seed_hash = k.digest()

            return True
        return False

    def clear_for_new_height(self):
        # This will trigger updates for everything else
        self.transactions.clear()

class StratumSession(RPCSession):
    begun_loop: bool = False

    def __init__(self, node_username, node_password, node_port, tx: TransactionState, transport):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        tx.transport = self
        self.tx = tx
        self.node_username = node_username
        self.node_password = node_password
        self.node_port = node_port

    async def handle_request(self, request):
        if not isinstance(request, Request):
            handler = None
        else:
            if request.method == 'mining.subscribe':
                async def handle_subscribe(*args):
                    return ['00000000', 4]
                handler = handle_subscribe
            elif request.method == 'mining.authorize':
                async def authorize_handler(*args):
                    address = args[0].split('.')[0]
                    try:
                        if base58.b58decode_check(address)[0] != 111:
                            raise RPCError(1, f'{address} is not a p2pkh address')
                    except ValueError:
                        raise RPCError(1, f'{address} is not a valid address')
                    self.tx.my_address = address
                    return True
                handler = authorize_handler
            elif request.method == 'mining.submit':
                async def handle_submit(*args):
                    worker, job_id, nonce_hex, header_hex, mixhash_hex = args
                    temp_block_a, temp_block_b = self.tx.partial_block()
                    full_block = temp_block_a + bytes.fromhex(nonce_hex[2:] + mixhash_hex[2:]) + temp_block_b
                    full_block = len(full_block).to_bytes(4, 'little') + full_block
                    data = {
                        'jsonrpc':'2.0',
                        'id':'0',
                        'method':'submitblock',
                        'params':[full_block.hex()]
                    }
                    async with ClientSession() as session:
                        async with session.post(f'http://{self.node_username}:{self.node_password}@localhost:{self.node_port}', data=json.dumps(data)) as resp:
                            print(await resp.text())
                    return True
                handler = handle_submit
            else:
                handler = None
        return await handler_invocation(handler, request)()
            
async def execute():

    '''
    reader, writer = await asyncio.open_connection('rvn.2miners.com', 6060)
    writer.write('{"id": 1, "method": "mining.subscribe", "params": []}\n'.encode('utf8'))
    writer.write('{"params": ["RMbuKtJdFf66Pr31shRZFf7fk3QsgJHbPS.miner1", "x"], "id": 2, "method": "mining.authorize"}\n'.encode('utf8'))
    await writer.drain()
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))
    print(await reader.readuntil(b'\n'))

    exit()
    '''
    if len(sys.argv) < 5:
        print('arguments must be: proxy_port, node_username, node_password, node_port')
        exit(0)

    proxy_port = int(sys.argv[1])
    node_username = str(sys.argv[2])
    node_password = str(sys.argv[3])
    node_port = int(sys.argv[4])

    tx = TransactionState()

    session_generator = partial(StratumSession, node_username, node_password, node_port, tx)

    # This keeps a state of current mempool & generates upcoming txs
    async def query_loop():
        data = {
            'jsonrpc':'2.0',
            'id':'0',
            'method':'getblocktemplate',
            'params':[]
        }
        height = -1
        while True:
            async with ClientSession() as session:
                async with session.post(f'http://{node_username}:{node_password}@localhost:{node_port}', data=json.dumps(data)) as resp:
                    json_resp = await resp.json()
                    clear_work = False
                    if height != json_resp['result']['height']:
                        clear_work = True
                        tx.clear_for_new_height()
                        height = json_resp['result']['height']
                    should_notify = tx.update_transactions(
                        json_resp['result']['version'], 
                        json_resp['result']['height'], 
                        bytes.fromhex(json_resp['result']['bits']), 
                        int(time.time()),
                        bytes.fromhex(json_resp['result']['previousblockhash']),
                        json_resp['result']['transactions'], 
                        json_resp['result']['coinbasevalue'], 
                        bytes.fromhex(json_resp['result']['default_witness_commitment']))
                    if should_notify and tx.transport:
                        await tx.transport.send_notification('mining.set_target', (json_resp['result']['target'],))
                        await tx.transport.send_notification('mining.notify', ('0', tx.header_hash.hex(), tx.seed_hash.hex(), json_resp['result']['target'], clear_work, height, json_resp['result']['bits']))
            await asyncio.sleep(0.1)

    async with TaskGroup() as group:
        await group.spawn(serve_rs(session_generator, None, proxy_port, loop=asyncio.get_event_loop(), reuse_address=True))
        await group.spawn(query_loop())

    for task in group.tasks:
        if not task.cancelled():
            exc = task.exception()
            if exc:
                raise exc

if __name__ == '__main__':
    asyncio.run(execute())
