'''Acts as a proxy and prints network traffic (for debugging)'''

import sys
import os
import socket
import select

if __name__ == '__main__':
    def check_bool(x) -> bool:
        if isinstance(x, str):
            return x.lower()[0] == 't'
        return bool(x)

    if len(sys.argv) < 4:
        print('Required args: (this port), (mining pool ip/url), (mining pool port), (allow external connections(opional))')
        exit()

    port = int(sys.argv[1])
    pool_url = str(sys.argv[2])
    pool_port = int(sys.argv[3])
    should_listen_externaly = False
    if len(sys.argv) > 4:
        should_listen_externaly = check_bool(sys.argv[4])


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as outgoing:
        outgoing.connect((pool_url, pool_port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as incoming:
            incoming.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if should_listen_externaly:
                incoming.bind(('0.0.0.0', port))
            else:
                incoming.bind(('127.0.0.1', port))
            incoming.listen()
            incoming_conn, addr = incoming.accept()
            with incoming_conn:
                print(f'Got connection from {addr}')
                while True:
                    rlist, _, _ = select.select([outgoing, incoming_conn], [], [])
                    for sock in rlist:
                        data = sock.recv(1024 * 5) # 5KB should be enough
                        if sock == outgoing:
                            print(f'Incoming:\n{data}\n===')
                            incoming_conn.sendall(data)
                        else:
                            print(f'Outgoing:\n{data}\n===')
                            outgoing.sendall(data)
