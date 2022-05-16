import asyncio
from hashlib import sha256
from os import urandom
import sys
from functools import partial
import base58
import json
from typing import List
from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCAutoDetect, JSONRPCConnection, serve_rs, handler_invocation, RPCError, TaskGroup
from aiorpcx.jsonrpc import Request

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
    update_coinbase_every = 100
    update_counter = update_coinbase_every
    my_address = None
    merkle = None

    def build_coinbase_transaction(self, my_address: str, my_sats: int, witness_commitment: bytes):
        arbitrary_data = 'converted with kralverde and the help of nonce: '.encode('utf8') + urandom(0x10)
        coinbase_txin = bytes(32) + b'\xff\xff\xff\xff' + bytes([len(arbitrary_data)]) + arbitrary_data + b'\xff\xff\xff\xff'
        vout1 = b'\x76\xa9\x14' + base58.b58decode(my_address)[1:] + b'\x88\xac'
        self.coinbase = int(1).to_bytes(4, 'little') + \
                        b'\x00\x01' + \
                        b'\x01' + coinbase_txin + \
                        b'\x02' + \
                            my_sats.to_bytes(8, 'little') + bytes([len(vout1)]) + vout1 + \
                            bytes(8) + bytes([len(witness_commitment)]) + witness_commitment + \
                        b'\x01\x20' + bytes(32) + bytes(4)

    def update_transactions(self, new_transactions, my_sats, witness_commitment):
        self.update_counter += 1
        changed_mine = False
        if self.my_address and self.update_counter >= self.update_coinbase_every:
            self.update_counter = 0
            changed_mine = True
            self.build_coinbase_transaction(self.my_address, my_sats, witness_commitment)
        if self.my_address and (changed_mine or len(self.transactions) != len(new_transactions)):
            # recalculate everything
            new_transactions = [self.coinbase]
            transaction_ids = [bytes(reversed(dsha256(self.coinbase)))]
            for tx_data in new_transactions:
                raw_tx_hex = tx_data['data']
                tx_hash = tx_data['txid']
                new_transactions.append(bytes.fromhex(raw_tx_hex))
                transaction_ids.append(bytes(reversed(bytes.fromhex(tx_hash))))
            self.transactions = new_transactions
            self.merkle = merkle_from_txids(transaction_ids)
            return True
        return False

    def clear_for_new_height(self):
        self.transactions.clear()
        self.merkle = None

class StratumSession(RPCSession):
    begun_loop: bool = False

    def __init__(self, tx: TransactionState, transport):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        tx.transport = self
        self.tx = tx

    async def handle_request(self, request):
        if not isinstance(request, Request):
            handler = None
        else:
            if request.method == 'mining.subscribe':
                print(request.args)
                handler = lambda: ['00000000', 4]
            elif request.method == 'mining.authorize':
                address = request.args[0]
                try:
                    if base58.b58decode_check(address)[0] != 111:
                        raise RPCError(1, f'{address} is not a p2pkh address')
                except ValueError:
                    raise RPCError(1, f'{address} is not a valid address')
                handler = lambda: True
                self.tx.my_address = address
            elif request.method == 'mining.submit':
                worker, job_id, nonce_hex, header_hex, mixhash_hex = request.args
                print(worker, job_id, nonce_hex, header_hex, mixhash_hex)
            else:
                handler = None
        return await handler_invocation(handler, request)()
            
async def execute():

    if len(sys.argv) < 5:
        print('arguments must be: proxy_port, node_username, node_password, node_port')
        exit(0)

    proxy_port = int(sys.argv[1])
    node_username = str(sys.argv[2])
    node_password = str(sys.argv[3])
    node_port = int(sys.argv[4])

    tx = TransactionState()

    session_generator = partial(StratumSession, tx)

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
                    should_notify = tx.update_transactions(json_resp['result']['transactions'], json_resp['result']['coinbasevalue'], bytes.fromhex(json_resp['result']['default_witness_commitment']))
                    if should_notify and tx.transport:
                        rev_prev_hash = bytes(reversed(bytes.fromhex(json_resp['result']['previousblockhash'])))
                        tx.transport.send_notification('mining.notify', ('0', rev_prev_hash, tx.merkle.hex(), json_resp['result']['target'], clear_work, height, json_resp['result']['bits']))
                        print('Notifying')
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
