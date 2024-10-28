import win32.win32evtlog as win32evtlog
from datetime import datetime, timedelta
import socket
import threading
import time

hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

SERVER_HOST = '127.0.0.1'  # Change to your actual server IP if needed
SERVER_PORT = 65432   

# Shared log list to store logs to be sent
shared_logs = []
log_lock = threading.Lock()  # Lock to synchronize access to shared_logs

def get_recent_windows_logs(log_type, minutes=0.205):
    while True:
        try:
            # Open log each time to ensure fresh handle
            hand = win32evtlog.OpenEventLog(None, log_type)
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            
            new_logs = []
            for event in events:
                if event.TimeGenerated >= cutoff_time:
                    log = f"""
                    Event ID: {event.EventID}
                    Event Category: {event.EventCategory}
                    Event Type: {event.EventType}
                    Computer Name: {event.ComputerName}
                    Hostname: {hostname}
                    IP Address: {ip_address}
                    Source Name: {event.SourceName}
                    Record Number: {event.RecordNumber}
                    Closing Record Number: {event.ClosingRecordNumber}
                    Reserved: {event.Reserved}
                    Reserved Flags: {event.ReservedFlags}
                    SID: {event.Sid}
                    Data: {event.Data}
                    String Inserts: {event.StringInserts}
                    Time Generated: {event.TimeGenerated}
                    Time Written: {event.TimeWritten}
                    Description: {event.StringInserts}
                    """
                    new_logs.append(log)
            
            with log_lock:
                shared_logs.extend(new_logs)

            # Close log handle each iteration
            win32evtlog.CloseEventLog(hand)
            
            # Adjust frequency of log checks
            time.sleep(12)
        
        except Exception as e:
            print(f"Error in get_recent_windows_logs: {e}")
            time.sleep(5)  # Pause briefly if an error occurs

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print("[*] Connected to server.")

            while True:
                with log_lock:
                    if shared_logs:
                        for message in shared_logs:
                            client_socket.sendall(message.encode("utf-8"))
                            response = client_socket.recv(1024).decode("utf-8")
                            print(f"[<] Server response: {response}")
                        shared_logs.clear()

                time.sleep(5)

        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    # Start the logging thread
    logging_thread = threading.Thread(target=get_recent_windows_logs, args=('Application',))
    logging_thread.daemon = True  # Daemonize thread to close with the program
    logging_thread.start()

    # Start the client connection
    start_client()
