'''No unit tests lol just for debugging correct creation of blocks'''

from hashlib import sha256

def read_var_int(b: bytes):
    if b[0] < 0xFD:
        return 1, b[0]
    if b[0] == 0xFD:
        return 3, int.from_bytes(b[1:3], 'big')
    if b[0] == 0xFE:
        return 5, int.from_bytes(b[1:5], 'big')
    else:
        return 9, int.from_bytes(b[1:9], 'big')

def dsha256(b):
    return sha256(sha256(b).digest()).digest()

def decode_block_hex(h: str):
    b = bytes.fromhex(h)
    #size = b[:4]
    #b = b[4:]
    #print(f'block size: {size.hex()} ({int.from_bytes(size, "big")})')
    v = b[:4]
    b = b[4:]

    # Header
    print(f'version: {v.hex()} ({int.from_bytes(v, "little")})')
    prev_hash = b[:32]
    b = b[32:]
    print(f'prevhash: {prev_hash.hex()} ({prev_hash[::-1].hex()})')
    merkle_root = b[:32]
    b = b[32:]
    print(f'merkle root: {merkle_root.hex()} ({merkle_root[::-1].hex()})')
    ts = b[:4]
    b = b[4:]
    print(f'timestamp: {ts.hex()} ({int.from_bytes(ts, "little")})')
    bits = b[:4]
    b = b[4:]
    print(f'bits: {bits.hex()} ({int.from_bytes(bits, "little")})')
    nheight = b[:4]
    b = b[4:]
    print(f'nheight: {nheight.hex()} ({int.from_bytes(nheight, "little")})')
    nonce = b[:8]
    b = b[8:]
    print(f'nonce: {nonce.hex()} ({int.from_bytes(nonce, "little")})')
    mix_hash = b[:32]
    b = b[32:]
    print(f'mix hash: {mix_hash.hex()} ({mix_hash[::-1].hex()})')

    # Actual block
    cut, num_transactions = read_var_int(b)
    b = b[cut:]
    print(f'number of tranasctions: {num_transactions}')

    wit_flag = False
    for i in range(num_transactions):
        v = b[:4]
        b = b[4:]
        print(f'transaction {i} version: {v.hex()} ({int.from_bytes(v, "little")})')
        if b[0] == 0:
            assert b[1] == 1
            print(f'transaction {i}: flag is present')
            b = b[2:]
            wit_flag = True

        tx_b = b''
        cut, num_vins = read_var_int(b)
        tx_b += b[:cut]
        b = b[cut:]
        print(f'transaction {i} vin count: {num_vins}')
        for j in range(num_vins):
            prev_txid = b[:32]
            tx_b += b[:32]
            b = b[32:]
            print(f'transaction {i} vin {j} prev txid: {prev_txid.hex()} ({prev_txid[::-1].hex()})')
            prev_idx = b[:4]
            tx_b += b[:4]
            b = b[4:]
            print(f'transaction {i} vin {j} prev idx: {prev_idx.hex()} ({int.from_bytes(prev_idx, "little")})')
            cut, script_length = read_var_int(b)
            tx_b += b[:cut]
            b = b[cut:]
            script = b[:script_length]
            tx_b += b[:script_length]
            b = b[script_length:]
            print(f'transaction {i} vin {j} script: {script.hex()}')
            sequence = b[:4]
            tx_b += b[:4]
            b = b[4:]
            print(f'transaction {i} vin {j} sequence: {sequence.hex()} ({int.from_bytes(sequence, "little")})')

        cut, num_vouts = read_var_int(b)
        tx_b += b[:cut]
        b = b[cut:]

        print(f'transaction {i} vout count: {num_vouts}')
        for j in range(num_vouts):
            value = b[:8]
            tx_b += b[:8]
            b = b[8:]
            print(f'transaction {i} vout {j} value: {value.hex()} ({int.from_bytes(value, "little")})')
            cut, script_length = read_var_int(b)
            tx_b += b[:cut]
            b = b[cut:]
            script = b[:script_length]
            tx_b += b[:script_length]
            b = b[script_length:]
            print(f'transaction {i} vout {j} script: {script.hex()}')
        
        if wit_flag:
            for j in range(num_vins):
                cut, wit_for_in = read_var_int(b)
                b = b[cut:]
                print(f'transaction {i} vin {j} has witness count {wit_for_in}')
                for _ in range(wit_for_in):
                    cut, data_len = read_var_int(b)
                    b = b[cut:]
                    data = b[:data_len]
                    b = b[data_len:]
                    print(f'transaction {i} vin {j} witness data: {data.hex()} (len: {data_len})')

        lock_time = b[:4]
        tx_b += b[:4]
        b = b[4:]
        print(f'transaction {i} locktime: {lock_time.hex()} ({int.from_bytes(lock_time, "little")})')
        print(f'transaction {i} txid: {dsha256(tx_b).hex()}')

    print(f'left over: {b.hex()}')

if __name__ == '__main__':
    #decode_block_hex('00000030607b67b4196b0442c083a7b06bde0fad4775ec738bdb34c4adb9b1d75600000051566ef8593340e6ff59875b97c67628e73f098754e67933e86c012a9572215caee08162bd4f631d804f12004f65044c56b6dd92954e2879d636114a9ea03f9b6dfe5ae704096858d61c3faf00297d743542651e01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0503804f1200ffffffff020088526a740000001976a914c6ba953c0f116181a4fe6b62735e07a6786a85f488ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')
    #decode_block_hex('000000308ef3bca04f09ac100760e881022c20ab2f6706756f7ad188025620fb55000000e1d1c9ac9d108a11e9766f8bce53bd95317460fb9b8f60d6e44bbb0ec794ca1c2ea283629efd6c1d1f55120086b4d40000000040f3cc49ca6b0652f9bb1955780bf1ac3fb7067b6dcfba2addb1c7cf2c2034548501010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff6b636f6e7665727465642077697468207468652068656c70206f662068747470733a2f2f6769746875622e636f6d2f6b72616c76657264652f726176656e636f696e2d7374726174756d2d70726f787920616e64206e6f6e63653a2099d844c8a49f47e0d18f1143d96927d5ffffffff020088526a740000001d76a91473da38c83935a151bb1455f297398e1159abd1c1458accb588ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')

    import asyncio
    
    async def run():
        reader, writer = await asyncio.open_connection('localhost', 42069)
        writer.write(b'TEST')
        await writer.drain()
        await asyncio.sleep(0)
        await reader.read()

    asyncio.run(run())
