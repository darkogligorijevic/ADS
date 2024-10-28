import ollama
import socket

# Definisanje server hosta i porta
HOST = '0.0.0.0'  # Slušaj na svim interfejsima
PORT = 65432      # Port koji ćeš koristiti za server
OLLAMA_SERVER_URL = "http://localhost:11434"  # Zameni sa tačnom IP adresom i portom vašeg Ollama servera

# Postavljanje baznog URL-a pre nego što se funkcija koristi
ollama.api_url = OLLAMA_SERVER_URL

def parsed_logs():
    pass

def raw_logs(): 
    pass

def chat_with_ollama(prompt):
    try:
        # Pravilno korišćenje chat funkcije sa modelom "dolphin-mistral"
        response = ollama.chat(model="dolphin-mistral",
                               messages=[{"role": "user", "content": prompt}])
        
        # Pristupamo odgovoru unutar message["content"]
        return response["message"]["content"] if "message" in response and "content" in response["message"] else "Nema odgovora od Ollame."
    
    except Exception as e:
        return f"Greška prilikom komunikacije: {e}"

def handle_client(conn, addr):
    print(f"[+] Konekcija sa {addr} je uspostavljena.")

    try:
        while True:
            # Prima podatke od klijenta
            data = conn.recv(1024)  # Čitanje do 1024 bajta odjednom
            
            if not data:
                # Ako nema više podataka, klijent je zatvorio konekciju
                print(f"[-] Klijent {addr} je prekinuo vezu.")
                break

            # Obrada primljenih podataka
            message = data.decode("utf-8")
            responsee = chat_with_ollama(message)
            print(responsee)

            # Slanje odgovora klijentu (opciono)
            conn.sendall(b"Poruka primljena!")
        
    except Exception as e:
        print(f"[-] Greska: {e}")
    finally:
        conn.close()
        print(f"[-] Konekcija sa {addr} je zatvorena.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print("[*] Server pokrenut i slusa za dolazece konekcije...")

        while True:
            # Prihvatanje dolazne konekcije
            conn, addr = server_socket.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    firstResponse = chat_with_ollama("I will be sending Windows Event Logs for you to analyze them and tell me if they are potentially suspicious/risky/malicious or clean/safe, check for suspicious program names, logins... I am a program programmed to send you logs, please if you recognize any suspicious app name or hacktool tell us, some of hacktools for example but not limited to are nmap, john, wireshark... I won't be able to send you any more information except logs.")
    print(firstResponse)
    start_server()