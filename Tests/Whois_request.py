import socket

def whois_query(query, server="whois.ripe.net", port=43):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, port))
        s.send((query + "\r\n").encode())
        response = b""
        while True:
            piece = s.recv(4096)
            if not piece:
                break
            response += piece
    return response.decode()

query = "193.0.6.139"
response = whois_query(query)

for line in response.splitlines():
    if line.strip():
        print(f"  {line.strip()}")