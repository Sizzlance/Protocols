import socket
import threading
import argparse
from queue import Queue
import re

PROTOCOL_SIGNATURES = {
    b'HTTP/1.[01]': 'HTTP',
    b'^220[ -].*SMTP': 'SMTP',
    b'^\* OK': 'IMAP',
    b'^\+OK': 'POP3',
    b'^\x1b': 'NTP',
    b'^\x00[\x00-\x0F]\x00': 'DNS'
}


def detect_protocol(port, data):
    if not data:
        return None

    for pattern, protocol in PROTOCOL_SIGNATURES.items():
        if re.search(pattern, data, re.IGNORECASE | re.MULTILINE):
            return protocol

    if port == 80 and b'<' in data and b'>' in data:
        return 'HTTP'
    elif port == 53 and len(data) > 4:
        return 'DNS'
    elif port == 123 and len(data) >= 48:
        return 'NTP'
    elif port == 25 and (b'220' in data or b'SMTP' in data):
        return 'SMTP'
    elif port == 110 and b'+OK' in data:
        return 'POP3'
    elif port == 143 and b'* OK' in data:
        return 'IMAP'

    return None


def tcp_scan(host, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            try:
                data = s.recv(1024)
                protocol = detect_protocol(port, data)
                return ('TCP', port, protocol)
            except (socket.timeout, socket.error):
                if port == 80:
                    return ('TCP', port, 'HTTP')
                elif port == 443:
                    return ('TCP', port, 'HTTPS')
                return ('TCP', port, None)
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return None


def udp_scan(host, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'', (host, port))

            try:
                data, _ = s.recvfrom(1024)
                protocol = detect_protocol(port, data)
                return ('UDP', port, protocol)
            except socket.timeout:
                if port == 53:
                    dns_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                    s.sendto(dns_query, (host, port))
                    try:
                        data, _ = s.recvfrom(1024)
                        return ('UDP', port, 'DNS')
                    except socket.timeout:
                        pass
                elif port == 123:
                    ntp_query = b'\x1b' + 47 * b'\0'
                    s.sendto(ntp_query, (host, port))
                    try:
                        data, _ = s.recvfrom(1024)
                        return ('UDP', port, 'NTP')
                    except socket.timeout:
                        pass

                return ('UDP', port, None)
    except (socket.timeout, socket.error):
        return None


def worker(host, scan_func, queue, results):
    while not queue.empty():
        port = queue.get()
        result = scan_func(host, port)
        if result:
            results.append(result)
        queue.task_done()


def main():
    parser = argparse.ArgumentParser(description='TCP/UDP Port Scanner')
    parser.add_argument('host', help='Host to scan')
    parser.add_argument('-t', '--tcp', action='store_true', help='Scan TCP ports')
    parser.add_argument('-u', '--udp', action='store_true', help='Scan UDP ports')
    parser.add_argument('-p', '--ports', nargs=2, type=int, metavar=('START', 'END'),
                        help='Port range to scan', required=True)

    args = parser.parse_args()

    if not args.tcp and not args.udp:
        print("Выберите хотя бы 1 протокол (-t для TCP, -u для UDP)")
        return

    start_port, end_port = args.ports
    if start_port > end_port:
        start_port, end_port = end_port, start_port

    if args.udp or (start_port < 1024 or end_port < 1024):
        try:
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM).bind(('', 53))
        except PermissionError:
            print("Не хватает прав для получения полных результатов")

    results = []

    if args.tcp:
        print(f"Scanning TCP ports {start_port}-{end_port}")
        tcp_queue = Queue()
        for port in range(start_port, end_port + 1):
            tcp_queue.put(port)

        threads = []
        for _ in range(50):
            thread = threading.Thread(target=worker, args=(args.host, tcp_scan, tcp_queue, results))
            thread.start()
            threads.append(thread)

        tcp_queue.join()

    if args.udp:
        print(f"Scanning UDP ports {start_port}-{end_port}")
        udp_queue = Queue()
        for port in range(start_port, end_port + 1):
            udp_queue.put(port)

        threads = []
        for _ in range(20):
            thread = threading.Thread(target=worker, args=(args.host, udp_scan, udp_queue, results))
            thread.start()
            threads.append(thread)

        udp_queue.join()

    for result in sorted(results, key=lambda x: (x[0], x[1])):
        proto, port, app_proto = result
        if app_proto:
            print(f"{proto} {port} {app_proto}")
        else:
            if proto == 'TCP':
                if port == 25:
                    print(f"{proto} {port} SMTP")
                elif port == 80:
                    print(f"{proto} {port} HTTP")
                elif port == 110:
                    print(f"{proto} {port} POP3")
                elif port == 143:
                    print(f"{proto} {port} IMAP")
            elif proto == 'UDP':
                if port == 53:
                    print(f"{proto} {port} DNS")
                elif port == 123:
                    print(f"{proto} {port} NTP")

if __name__ == '__main__':
    main()