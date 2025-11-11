import socket
from des import des_encrypt_ecb, des_decrypt_ecb

HOST = input("Enter the server's IP address: ").strip()
PORT = 65432

key = input("Enter 8-character key: ").encode("utf-8")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        print(f"Connected to server {HOST}:{PORT}")
        print("You talk first. Type 'exit' to quit.")

        while True:
            # client mengirim pesan
            message = input("[You]: ")
            plaintext = message.encode('utf-8')
            ciphertext = des_encrypt_ecb(plaintext, key)
            
            print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")

            s.sendall(ciphertext)

            if message.lower() == 'exit':
                print("[You have disconnected]")
                break

            # client menunggu balasan
            print("[Waiting for server's reply...]")
            data = s.recv(1024)
            if not data:
                print("\n[Server disconnected]")
                break
            
            print(f"[Received Ciphertext (hex)]: {data.hex()}")

            decrypted = des_decrypt_ecb(data, key).decode('utf-8', errors='ignore')
            print(f"[Server]: {decrypted}")

            if decrypted.lower() == 'exit':
                print("[Server has disconnected]")
                break

    except ConnectionRefusedError:
        print(f"Could not connect to server at {HOST}:{PORT}.")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("Connection closed.")