import socket
import ssl
import getpass
import argparse
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime


class IMAPClient:
    def __init__(self, server, port, use_ssl=True):
        self.server = server
        self.port = port
        self.use_ssl = use_ssl
        self.socket = None
        self.connection = None
        self.tag_counter = 0
        self.buffer = b''

    def connect(self):
        """Устанавливает соединение с IMAP-сервером"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(10)  # Таймаут 10 секунд
        self.socket.connect((self.server, self.port))

        if self.use_ssl:
            context = ssl.create_default_context()
            self.connection = context.wrap_socket(self.socket, server_hostname=self.server)
        else:
            self.connection = self.socket

        response = self._receive_response()
        if not response.startswith(b'* OK'):
            raise Exception(f"Server error: {response.decode('utf-8', errors='replace')}")

    def _next_tag(self):
        """Генерирует следующий тег команды"""
        self.tag_counter += 1
        return f"A{self.tag_counter:04d}"

    def _send_command(self, command):
        """Отправляет команду на сервер"""
        tag = self._next_tag()
        full_command = f"{tag} {command}\r\n".encode()
        self.connection.sendall(full_command)
        return tag

    def _receive_response(self):
        """Получает ответ от сервера"""
        response = b''
        while True:
            try:
                data = self.connection.recv(4096)
                if not data:
                    break
                response += data
                if self._next_tag().encode() in response:
                    break
            except socket.timeout:
                break
        return response

    def login(self, username, password):
        """Аутентификация на сервере"""
        tag = self._send_command(f'LOGIN "{username}" "{password}"')
        response = self._receive_response()

        if not any(line.startswith(f"{tag} OK".encode()) for line in response.split(b'\r\n')):
            raise Exception(f"Login failed: {response.decode('utf-8', errors='replace')}")

    def select(self, mailbox='INBOX'):
        """Выбирает почтовый ящик"""
        tag = self._send_command(f'SELECT "{mailbox}"')
        response = self._receive_response()
        if not any(line.startswith(f"{tag} OK".encode()) for line in response.split(b'\r\n')):
            raise Exception(f"Select failed: {response.decode('utf-8', errors='replace')}")

    def search(self, criteria='ALL'):
        """Поиск писем по критерию"""
        tag = self._send_command(f'SEARCH {criteria}')
        response = self._receive_response()

        if not any(line.startswith(f"{tag} OK".encode()) for line in response.split(b'\r\n')):
            raise Exception(f"Search failed: {response.decode('utf-8', errors='replace')}")

        numbers = []
        for line in response.split(b'\r\n'):
            if line.startswith(b'* SEARCH'):
                numbers = line[8:].strip().split()
        return [num.decode() for num in numbers]

    def fetch(self, message_id, data_item='(RFC822)'):
        """Получает содержимое письма"""
        tag = self._send_command(f'FETCH {message_id} {data_item}')
        response = self._receive_response()

        if not any(line.startswith(f"{tag} OK".encode()) for line in response.split(b'\r\n')):
            raise Exception(f"Fetch failed: {response.decode('utf-8', errors='replace')}")

        raw_email = b''
        for line in response.split(b'\r\n'):
            if line.startswith(b'*') and b'FETCH' in line:
                continue
            if line.startswith(tag.encode()):
                break
            raw_email += line + b'\r\n'

        return raw_email

    def logout(self):
        """Завершает сеанс"""
        try:
            self._send_command('LOGOUT')
            self._receive_response()
        finally:
            self.connection.close()


def decode_mime_header(header):
    """Декодирует MIME-заголовок (From/Subject)"""
    if header is None:
        return ""

    decoded_parts = decode_header(header)
    decoded_str = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            decoded_str += part.decode(encoding or 'utf-8', errors='replace')
        else:
            decoded_str += part
    return decoded_str


def format_table_row(data, widths):
    """Форматирует строку таблицы с учётом ширины столбцов"""
    return " | ".join(f"{str(item):<{widths[i]}}" for i, item in enumerate(data))


def parse_email(raw_email):
    """Разбирает сырое письмо и извлекает нужные данные"""
    parser = BytesParser()
    email_message = parser.parsebytes(raw_email)

    from_ = decode_mime_header(email_message['From'])
    to = decode_mime_header(email_message.get('To', ''))
    subject = decode_mime_header(email_message.get('Subject', 'No Subject'))
    date = parsedate_to_datetime(email_message['Date']).strftime('%Y-%m-%d %H:%M:%S')
    size = len(raw_email)

    attachments = []
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
                size = len(part.get_payload(decode=True))
                attachments.append((filename, f"{size / 1024:.1f} KB"))

    return {
        'from': from_,
        'to': to,
        'subject': subject,
        'date': date,
        'size': f"{size / 1024:.1f} KB",
        'attachments': attachments
    }


def get_mail_info(server, port, use_ssl, username, password, mail_range=None):
    """Получает информацию о письмах с IMAP-сервера"""
    try:
        client = IMAPClient(server, port, use_ssl)
        print("Connecting to server...")
        client.connect()
        print("Logging in...")
        client.login(username, password)
        print("Selecting mailbox...")
        client.select('INBOX')
        print("Searching messages...")
        message_numbers = client.search('ALL')

        if mail_range:
            start, end = mail_range
            start = max(1, int(start))
            end = min(len(message_numbers), int(end)) if end else len(message_numbers)
            message_numbers = message_numbers[start - 1:end]

        col_widths = [30, 30, 40, 20, 10]
        headers = ["From", "To", "Subject", "Date", "Size"]
        print(format_table_row(headers, col_widths))
        print("-" * (sum(col_widths) + 3 * (len(col_widths) - 1)))

        for num in message_numbers:
            print(f"Fetching message {num}...")
            raw_email = client.fetch(num, '(RFC822)')
            email_data = parse_email(raw_email)

            row_data = [
                email_data['from'],
                email_data['to'],
                email_data['subject'],
                email_data['date'],
                email_data['size']
            ]
            print(format_table_row(row_data, col_widths))

            if email_data['attachments']:
                print(f"\nMessage {num}: {len(email_data['attachments'])} attachments")
                for filename, size in email_data['attachments']:
                    print(f"  {filename} ({size})")

        client.logout()
        print("Done.")

    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='IMAP mailbox reader (socket version)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL (default: False)')
    parser.add_argument('-s', '--server', required=True, help='IMAP server address[:port]')
    parser.add_argument('-n', nargs='+', type=int, help='Mail range N1 [N2]')
    parser.add_argument('-u', '--user', required=True, help='Username')
    args = parser.parse_args()

    server_parts = args.server.split(':')
    server = server_parts[0]
    port = int(server_parts[1]) if len(server_parts) > 1 else (993 if args.ssl else 143)

    mail_range = None
    if args.n:
        mail_range = (args.n[0], args.n[1] if len(args.n) > 1 else None)

    password = getpass.getpass(f"Password for {args.user}: ")

    get_mail_info(server, port, args.ssl, args.user, password, mail_range)


if __name__ == "__main__":
    main()