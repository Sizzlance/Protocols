import socket
import time
import struct
import threading
import argparse


def get_ntp_time(server='pool.ntp.org'):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)

            data = bytearray(48)
            data[0] = (3 << 6) | (4 << 3) | 3

            start = time.time()
            client.sendto(data, (server, 123))
            data, _ = client.recvfrom(1024)
            end = time.time()

            transmit_timestamp = struct.unpack('!Q', data[40:48])[0]
            ntp_time = (transmit_timestamp >> 32) - 2208988800
            fractional = (transmit_timestamp & 0xFFFFFFFF) / 2 ** 32

            return (ntp_time + fractional) + ((end - start) / 2)
    except Exception:
        return time.time()


def sntp_server(delay, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', port))
    print(f"Server started on port {port} with delay {delay} seconds")

    while True:
        data, addr = server_socket.recvfrom(1024)
        print(f"Client connected: {addr[0]}")
        threading.Thread(target=handle_client, args=(data, addr, server_socket, delay)).start()


def handle_client(data, addr, server_socket, delay):
    try:
        if len(data) < 48:
            print(f"Invalid packet from {addr[0]}")
            return

        li_vn_mode = data[0]
        mode = li_vn_mode & 0x07

        if mode == 3:
            response = bytearray(48)
            response[0] = (0 << 6) | (4 << 3) | 4
            response[1] = 1

            ntp_time = get_ntp_time() + delay
            ntp_timestamp = int(ntp_time + 2208988800)
            fractional = int((ntp_time - int(ntp_time)) * 2 ** 32)
            packed_time = (ntp_timestamp << 32) | fractional

            response[16:24] = struct.pack('!Q', packed_time)
            response[24:32] = data[40:48] if len(data) >= 48 else b'\x00' * 8
            response[32:40] = struct.pack('!Q', packed_time)
            response[40:48] = struct.pack('!Q', packed_time)

            server_socket.sendto(response, addr)
    except Exception as e:
        print(f"Error handling client {addr[0]}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SNTP Server")
    parser.add_argument('-d', '--delay', type=float, default=0.0, help="Time offset in seconds")
    parser.add_argument('-p', '--port', type=int, default=123, help="Port to listen on")
    args = parser.parse_args()

    sntp_server(args.delay, args.port)