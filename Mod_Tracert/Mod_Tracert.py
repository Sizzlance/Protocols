import sys
import socket
import struct

def validate_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def resolve_dns(dns_name):
    try:
        return socket.gethostbyname(dns_name)
    except socket.error:
        return None

def get_whois_info(ip):
    whois_server = 'whois.iana.org'

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                s.connect((whois_server, 43))
            except socket.error as e:
                print(f"Ошибка при подключении к {whois_server}: {e}")
                return None, None, None

            try:
                s.send((ip + '\r\n').encode())
            except socket.error as e:
                print(f"Ошибка при отправке запроса: {e}")
                return None, None, None

            response = b''
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    print("Таймаут при получении данных.")
                    break
                except socket.error as e:
                    print(f"Ошибка при получении данных: {e}")
                    break

        whois_data = response.decode()

        regional_whois_server = None
        for line in whois_data.splitlines():
            if line.startswith('refer:'):
                regional_whois_server = line.split(':', 1)[1].strip()
                break

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)

            try:
                s.connect((regional_whois_server, 43))
            except socket.error as e:
                print(f"Ошибка при подключении к {regional_whois_server}: {e}")
                return None, None, None
            try:
                s.send((ip + '\r\n').encode())
            except socket.error as e:
                print(f"Ошибка при отправке запроса: {e}")
                return None, None, None

            response = b''
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    print("Таймаут при получении данных.")
                    break
                except socket.error as e:
                    print(f"Ошибка при получении данных: {e}")
                    break

        regional_whois_data = response.decode()

        print(regional_whois_data)

        org = None
        asn = None
        country = None

        for line in regional_whois_data.splitlines():
            if line.startswith('org-name:'):
                org = line.split(':', 1)[1].strip()
            elif line.startswith('origin:'):
                asn = line.split(':', 1)[1].strip()
            elif line.startswith('country:'):
                country = line.split(':', 1)[1].strip()

        return org, asn, country
    except Exception as e:
        print(f"Ошибка при запросе WHOIS: {e}")
        return None, None, None

def checksum(source_string):
    total = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        total = total + this_val
        total = total & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        total = total + source_string[len(source_string) - 1]
        total = total & 0xffffffff

    total = (total >> 16) + (total & 0xffff)
    total = total + (total >> 16)
    answer = ~total
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet():
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 1
    icmp_seq = 1

    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_checksum = checksum(header)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    return header

def traceroute(destination, max_hops=30):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)

        for ttl in range(1, max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            packet = create_icmp_packet()
            sock.sendto(packet, (destination, 0))

            if sys.argv[1] == '-d':
                try:
                    reply, addr = sock.recvfrom(1024)
                    ip = addr[0]

                    if ip:
                        print(f"{ttl}. {ip}\r\n")
                        if ip == destination:
                            break
                except socket.timeout:
                    print(f"{ttl}. *\r\n")

            else:
                try:
                    reply, addr = sock.recvfrom(1024)
                    ip = addr[0]

                    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                        print(f"{ttl}. {ip}\r\nlocal\r\n")
                    else:
                        if ip:
                            org, asn, country = get_whois_info(ip)
                            info = []
                            if org:
                                info.append(org)
                            if asn:
                                info.append(asn)
                            if country:
                                info.append(country)
                            if info:
                                print(f"{ttl}. {ip}\r\n{', '.join(info)}\r\n")
                            else:
                                print(f"{ttl}. {ip}\r\n")
                        else:
                            print(f"{ttl}. {ip}\r\n")

                    if ip == destination:
                        break
                except socket.timeout:
                    print(f"{ttl}. *\r\n")
    except PermissionError:
        print("Ошибка: Недостаточно прав для создания RAW-сокета")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    address = sys.argv[1]
    #flag = sys.argv[1]

    if validate_ip(address):
        ip = address
    else:
        ip = resolve_dns(address)
        if not ip:
            print("Ошибка: Не удалось разрешить доменное имя.")
            sys.exit(1)
    traceroute(ip)