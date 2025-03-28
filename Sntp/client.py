import socket
import time
import struct


def start_client(host='localhost', port=123):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        request = bytearray(48)
        request[0] = (0 << 6) | (3 << 3) | 3

        client_socket.sendto(request, (host, port))
        print(f"Отправлен SNTP запрос на {host}:{port}")

        data, addr = client_socket.recvfrom(1024)
        print(f"Получен ответ от {addr}")

        transmit_time = struct.unpack('!Q', data[40:48])[0] >> 32
        ntp_time = transmit_time - 2208988800
        print(f"Время на сервере: {time.ctime(ntp_time)}")

if __name__ == "__main__":
    start_client()