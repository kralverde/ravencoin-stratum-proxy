import sys
import os
import socket
import select

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Required args: (this port), (mining pool ip)')
        exit()

    port = int(sys.argv[1])
    pool_url = str(sys.argv[2])
    splitted = pool_url.split(':')
    pool_port = int(splitted[-1])
    pool_ip = splitted[0].split('/')[-1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as outgoing:
        outgoing.connect((pool_ip, pool_port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as incoming:
            incoming.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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