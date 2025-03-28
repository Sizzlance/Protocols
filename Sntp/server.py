import socket
import time
import struct
import threading

def sntp_server(delay, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', port))

    while True:
        data, addr = server_socket.recvfrom(1024)
        print(f"Client connected: {addr[0]}")
        threading.Thread(target=handle_client, args=(data, addr, server_socket, delay)).start()

def handle_client(data, addr, server_socket, delay):
    li_vn_mode = data[0]
    mode = li_vn_mode & 0x07

    if mode == 3:
        response = bytearray(48)
        response[0] = (0 << 6) | (4 << 3) | 4

        transmit_time = int(time.time()) + 2208988800 + delay
        response[40:48] = struct.pack('!Q', transmit_time << 32)

        server_socket.sendto(response, addr)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SNTP Server")
    parser.add_argument('-d', '--delay', type=int, default=0, help="Delay in seconds")
    parser.add_argument('-p', '--port', type=int, default=123, help="Port to listen on")
    args = parser.parse_args()

    sntp_server(args.delay, args.port)