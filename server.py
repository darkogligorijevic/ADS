import ollama
import socket

# Define HOST and PORT
HOST = '0.0.0.0'  
PORT = 65432      
OLLAMA_SERVER_URL = "http://localhost:11434"  # Ollama default server on PORT 11434

# Base URL
ollama.api_url = OLLAMA_SERVER_URL

def parsed_logs():
    pass

def raw_logs(): 
    pass

def chat_with_ollama(prompt):
    try:
        # Using dolphin-mistral as an ollama model
        response = ollama.chat(model="dolphin-mistral",
                               messages=[{"role": "user", "content": prompt}])
        
        # Return message
        return response["message"]["content"] if "message" in response and "content" in response["message"] else "No response from Ollama."
    
    except Exception as e:
        return f"Error: {e}"

def handle_client(conn, addr):
    print(f"[+] Connected with {addr}.")

    try:
        while True:
            # Receiving message from client
            data = conn.recv(1024) 
            
            if not data:
                # Close if no more data
                print(f"[-] Client {addr} has terminated the connection.")
                break

            message = data.decode("utf-8")
            responsee = chat_with_ollama(message)
            print(responsee)

            # Send response to the client
            conn.sendall(b"Message received!")
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection with {addr} is closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print("[*] Listening...")

        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    firstResponse = chat_with_ollama("I will be sending Windows Event Logs for you to analyze them and tell me if they are potentially suspicious/risky/malicious or clean/safe, check for suspicious program names, logins... I am a program programmed to send you logs, please if you recognize any suspicious app name or hacktool tell us, some of hacktools for example but not limited to are nmap, john, wireshark... I won't be able to send you any more information except logs.")
    print(firstResponse)
    start_server()
