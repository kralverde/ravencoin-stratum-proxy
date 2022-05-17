import asyncio
from aiohttp import ClientSession
from hashlib import sha256
import base58
import json
import sha3
import time
import sys

from typing import List, Set, Optional

KAWPOW_EPOCH_LENGTH = 7500

class CloseConnection(Exception): pass

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


async def execute(this_port: int, node_url: str, node_username: str, node_password: str, node_port: int, testnet: bool):

    clients_to_notify: Set[asyncio.StreamWriter] = set()
    
    class State:
        address: Optional[str] = None
        target: Optional[str] = None  # hex of target
        bits: Optional[str] = None  # hex of bits
        height: int = -1  # height of block we are working on
        header_hash: Optional[str] = None # hex of current header hash
        seed_hash: Optional[bytes] = None # bytes of the seed hash
        header: Optional[str] = None # hex of the header
        coinbase_tx: Optional[str] = None # hex of the coinbase transaction
        coinbase_txid: Optional[bytes] = None
        general_txs: Optional[List[str]] = None # hex of other transactions
        waiting_for_new_block = False

    # A namespace for our junk
    state = State()

    def build_block(nonce: str, mixhash: str) -> str:
        return state.header + nonce + mixhash + var_int(len(state.general_txs) + 1).hex() + state.coinbase_tx + b''.join(state.general_txs)

    # TODO: Make this functional
    async def regenerate_parameters():
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
                    if json_obj.get('error'):
                        print(json_obj.get('error'))
                        raise Exception()
                    
                    version_hex: str = json_obj['result']['version']
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

                        # Generate seed hash #
                        if state.height == - 1 or height_int > state.height:
                            if not state.seed_hash:
                                seed_hash = bytes(32)
                                for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                    k = sha3.keccak_256()
                                    k.update(seed_hash)
                                    seed_hash = k.digest()
                                state.seed_hash = seed_hash
                            elif state.height % KAWPOW_EPOCH_LENGTH == 0:
                                # Hashing is expensive, so just use the old val
                                k = sha3.keccak_256()
                                k.update(state.seed_hash)
                                seed_hash = k.digest()
                                state.seed_hash = seed_hash
                        else:
                            # Maybe a chain reorg?
                            if state.height % KAWPOW_EPOCH_LENGTH - (state.height - height_int):
                                # We must go back an epoch; recalc
                                seed_hash = bytes(32)
                                for _ in range(height_int//KAWPOW_EPOCH_LENGTH):
                                    k = sha3.keccak_256()
                                    k.update(seed_hash)
                                    seed_hash = k.digest()
                                state.seed_hash = seed_hash

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
                                        b'\x01\x20' + bytes(32) + bytes(4)).hex()

                        coinbase_no_wit = int(1).to_bytes(4, 'little') + \
                                            b'\x01' + coinbase_txin + \
                                            b'\x02' + \
                                                coinbase_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner + \
                                                bytes(8) + op_push(len(witness_vout)) + witness_vout + \
                                            bytes(4)
                        state.coinbase_txid = dsha256(coinbase_no_wit)

                        # Done with coinbase #

                        # Create merkle & update txs

                        txids = [state.coinbase_txid]
                        incoming_txs = []
                        for tx_data in txs_list:
                            incoming_txs.append(tx_data['data'])
                            txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                        state.general_txs = incoming_txs
                        merkle = merkle_from_txids(txids)

                        # Done create merkle & update txs

                        state.header = bytes.fromhex(version_hex)[::-1].hex() + \
                                bytes.fromhex(prev_hash_hex)[::-1].hex() + \
                                merkle.hex() + \
                                ts.to_bytes(4, 'little').hex() + \
                                bytes.fromhex(bits_hex)[::-1].hex() + \
                                state.height.to_bytes(4, 'little')

                        state.header_hash = dsha256(state.header)[::-1].hex()

                        # Notify all
                        #'mining.notify', ('0', tx.header_hash.hex(), tx.seed_hash.hex(), json_resp['result']['target'], clear_work, height, json_resp['result']['bits'])
                        json_obj_set_target = {
                            'id': None,
                            'method':'mining.set_target',
                            'params': [state.target],
                        }
                        for writer in clients_to_notify:
                            writer.write(json.dumps(json_obj_set_target).encode('utf8') + b'\n')
                            asyncio.create_task(writer.drain())

                        json_obj_new_job = {
                            'id': None,
                            'method:':'mining.notify',
                            'params': [
                                'the only job',
                                state.header_hash,
                                seed_hash.hex(),
                                state.target,
                                True,
                                state.height,
                                state.bits
                            ]
                        }
                        for writer in clients_to_notify:
                            writer.write(json.dumps(json_obj_new_job).encode('utf8') + b'\n')
                            asyncio.create_task(writer.drain())
                    
                    elif len(state.general_txs) != len(txs_list):
                        # Create merkle & update txs

                        txids = [state.coinbase_txid]
                        incoming_txs = []
                        for tx_data in txs_list:
                            incoming_txs.append(tx_data['data'])
                            txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                        state.general_txs = incoming_txs
                        merkle = merkle_from_txids(txids)

                        # Done create merkle & update txs

                        state.header = bytes.fromhex(version_hex)[::-1].hex() + \
                                bytes.fromhex(prev_hash_hex)[::-1].hex() + \
                                merkle.hex() + \
                                ts.to_bytes(4, 'little').hex() + \
                                bytes.fromhex(bits_hex)[::-1].hex() + \
                                state.height.to_bytes(4, 'little')

                        state.header_hash = dsha256(state.header)[::-1].hex()

                        json_obj_new_job = {
                            'id': None,
                            'method:':'mining.notify',
                            'params': [
                                'the only job',
                                state.header_hash,
                                state.seed_hash.hex(),
                                state.target,
                                True,
                                state.height,
                                state.bits
                            ]
                        }
                        for writer in clients_to_notify:
                            writer.write(json.dumps(json_obj_new_job).encode('utf8') + b'\n')
                            asyncio.create_task(writer.drain())
                    
                except Exception as e:
                    import traceback
                    traceback.print_exc(e)
                    print('Unable to get getblocktemplate from the node, failing')
                    exit(1)
                

    async def client_routine(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # https://github.com/aeternity/protocol/blob/master/STRATUM.md
        try:
            subscribed = False
            while state.my_address or not subscribed:
                exception = None
                exception_obj = None
                result = await reader.readuntil(b'\n')
                try:
                    json_result = json.loads(result)
                    if json_result.get('method', None) == 'mining.subscribe':
                        subscribed = True
                        writer.write((json.dumps({
                            'id':json_result.get('id', None),
                            # This is dummy data
                            'result':['00000000', 4],
                            'error': None
                        }) + '\n').encode('utf8'))
                    elif json_result.get('method', None) == 'mining.authorize':
                        params = json_result.get('params', [])
                        if isinstance(params, List):
                            if len(params) > 0:
                                address = params[0]
                                try:
                                    if base58.b58decode_check(address)[0] != (111 if testnet else 60):
                                        exception = 'Address is for wrong network'
                                        exception_obj = address
                                    else:
                                        if not state.address:
                                            state.address = address

                                        writer.write((json.dumps({
                                            'id':json_result.get('id', None),
                                            # This is dummy data
                                            'result':True,
                                            'error': None
                                        }) + '\n').encode('utf8'))
                                except Exception:
                                    exception = 'Invalid address'
                                    exception_obj = address
                            else:
                                exception = f'Invalid params length {json_result.get("method", None)}'
                                exception_obj = params
                        else:
                            exception = f'Invalid params for {json_result.get("method", None)}'
                            exception = params
                    else:
                        print(f'Received bad initialization method: {json_result}')
                        exception = 'Unknown initialization method'
                        exception_obj = json_result.get('method', None)

                    if exception:
                        writer.write((json.dumps({
                            'id':json_result.get('id', None),
                            'result':None,
                            'error': [20, exception, exception_obj]
                        }) + '\n').encode('utf8'))
                    await writer.drain()
                except (json.JSONDecodeError, TypeError):
                    raise CloseConnection()

            # We are good to start mining now
            json_obj_set_target = {
                'id': None,
                'method':'mining.set_target',
                'params': [state.target],
            }
            writer.write(json.dumps(json_obj_set_target).encode('utf8') + b'\n')
            asyncio.create_task(writer.drain())

            json_obj_new_job = {
                'id': None,
                'method:':'mining.notify',
                'params': [
                    'the only job',
                    state.header_hash,
                    state.seed_hash.hex(),
                    state.target,
                    True,
                    state.height,
                    state.bits
                ]
            }
            writer.write(json.dumps(json_obj_new_job).encode('utf8') + b'\n')
            asyncio.create_task(writer.drain())

            clients_to_notify.add(writer)
            while True:
                raw_json = await reader.readuntil(b'\n')
                try:
                    json_obj = json.loads(raw_json)
                except (json.JSONDecodeError, TypeError):
                    raise CloseConnection()
                
                if json_obj.get('method', None) == 'mining.submit':
                    params = json_result.get('params', [])
                    if isinstance(params, List):
                        if len(params) > 0:
                            worker, job_id, nonce_hex, header_hex, mixhash_hex = params
                            block = build_block(my_address, nonce_hex[2:], mixhash_hex[2:])

                            print(block.hex())
                            data = {
                                'jsonrpc':'2.0',
                                'id':'0',
                                'method':'submitblock',
                                'params':[block.hex()]
                            }

                            exception = None
                            async with ClientSession() as session:
                                async with session.post(f'http://{node_username}:{node_password}@{node_url}:{node_port}', data=json.dumps(data)) as resp:
                                    json_resp = await resp.json()
                                    print(json_resp)
                                    if json_resp.get('error', None):
                                        exception = json_resp['error']
                                    if json_resp.get('result', None):
                                        exception = json_resp['result']

                            if exception:
                                writer.write((json.dumps({
                                    'id':json_result.get('id', None),
                                    'result':None,
                                    'error':[20, exception, None]
                                }) + '\n').encode('utf8'))
                            else:
                                writer.write((json.dumps({
                                    'id':json_result.get('id', None),
                                    'result':True,
                                    'error':None
                                    }) + '\n').encode('utf8'))
                            await writer.drain()

        except (CloseConnection, asyncio.IncompleteReadError):
            clients_to_notify.discard(writer)

    server = await asyncio.start_server(client_routine, 'localhost', this_port, reuse_address=True)
    
    asyncio.create_task(server.serve_forever())
    
    while True:
        await regenerate_parameters()
        await asyncio.sleep(0.1)

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
    if len(sys.argv > 6):
        testnet = bool(sys.argv[6])

    asyncio.run(execute(42069, 'localhost', 'user', 'pass', 18766, testnet))