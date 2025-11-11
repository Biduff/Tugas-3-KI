import socket
from des import des_decrypt_ecb, des_encrypt_ecb

HOST = '0.0.0.0'  # localhost
PORT = 65432        # arbitrary port

key = input("Enter 8-character key: ").encode("utf-8")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print("Connected by", addr)
        print("Waiting for client to talk first...")

        while True:
            # server menerima pesan
            data = conn.recv(1024)
            if not data:
                print("\n[Client disconnected]")
                break
            
            print(f"[Received Ciphertext (hex)]: {data.hex()}")
            
            decrypted = des_decrypt_ecb(data, key).decode('utf-8', errors='ignore')
            print(f"[Client]: {decrypted}")

            if decrypted.lower() == 'exit':
                print("[Client has disconnected]")
                break

            # server membalas
            message = input("[You]: ")
            plaintext = message.encode('utf-8')
            ciphertext = des_encrypt_ecb(plaintext, key)

            print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")

            conn.sendall(ciphertext)
            
            if message.lower() == 'exit':
                print("[You have disconnected]")
                break

    print("Connection closed.")