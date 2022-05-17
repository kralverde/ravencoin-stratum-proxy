
def read_var_int(b: bytes):
    if b[0] < 0xFD:
        return 1, b[0]
    if b[0] == 0xFD:
        return 3, int.from_bytes(b[1:3], 'big')
    if b[0] == 0xFE:
        return 5, int.from_bytes(b[1:5], 'big')
    else:
        return 7, int.from_bytes(b[1:9], 'big')

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

        cut, num_vins = read_var_int(b)
        b = b[cut:]

        print(f'transaction {i} vin count: {num_vins}')
        for j in range(num_vins):
            prev_txid = b[:32]
            b = b[32:]
            print(f'transaction {i} vin {j} prev txid: {prev_txid.hex()} ({prev_txid[::-1].hex()})')
            prev_idx = b[:4]
            b = b[4:]
            print(f'transaction {i} vin {j} prev idx: {prev_idx.hex()} ({int.from_bytes(prev_idx, "little")})')
            cut, script_length = read_var_int(b)
            b = b[cut:]
            script = b[:script_length]
            b = b[script_length:]
            print(f'transaction {i} vin {j} script: {script.hex()}')
            sequence = b[:4]
            b = b[4:]
            print(f'transaction {i} vin {j} sequence: {sequence.hex()} ({int.from_bytes(sequence, "little")})')

        cut, num_vouts = read_var_int(b)
        b = b[cut:]

        print(f'transaction {i} vout count: {num_vouts}')
        for j in range(num_vouts):
            value = b[:8]
            b = b[8:]
            print(f'transaction {i} vout {j} value: {value.hex()} ({int.from_bytes(value, "little")})')
            cut, script_length = read_var_int(b)
            b = b[cut:]
            script = b[:script_length]
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
        b = b[4:]
        print(f'transaction {i} locktime: {lock_time.hex()} ({int.from_bytes(lock_time, "little")})')

    print(f'left over: {b.hex()}')

if __name__ == '__main__':
    decode_block_hex('00000030607b67b4196b0442c083a7b06bde0fad4775ec738bdb34c4adb9b1d75600000051566ef8593340e6ff59875b97c67628e73f098754e67933e86c012a9572215caee08162bd4f631d804f12004f65044c56b6dd92954e2879d636114a9ea03f9b6dfe5ae704096858d61c3faf00297d743542651e01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0503804f1200ffffffff020088526a740000001976a914c6ba953c0f116181a4fe6b62735e07a6786a85f488ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')