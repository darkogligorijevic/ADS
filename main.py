import win32.win32evtlog as win32evtlog
import time
from datetime import datetime, timedelta
import ollama
import pymsgbox  
import socket

hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

# List of suspicious keywords and events
SUSPICIOUS_KEYWORDS = ['malware', 'trojan', 'unauthorized', 'access denied', 'failed login', 'ransomware']
SUSPICIOUS_EVENT_IDS = [4625, 4624, 4688, 4720, 1102]

# Check if the given log is SUS
def is_suspicious_event(event):

    # Check event IDs
    if event.EventID in SUSPICIOUS_EVENT_IDS:
        return True
    
    # Check keywords
    if event.StringInserts:
        for keyword in SUSPICIOUS_KEYWORDS:
            if any(keyword.lower() in str(item).lower() for item in event.StringInserts):
                return True
    
    # Return False if there is no SUS IDs or Keywords
    return False

# Get logs
def get_recent_windows_logs(log_type, minutes):
    # Open log
    hand = win32evtlog.OpenEventLog(None, log_type)
    # Read logs
    logs = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
    # Cutoff time by given minutes
    cutoff_time = datetime.now() - timedelta(minutes=minutes)
    
    # Go through logs and check for SUS logs
    for event in logs:
        event_time = event.TimeGenerated
        
        # If there is SUS log, forward to ollama and display it 
        if event_time >= cutoff_time and is_suspicious_event(event):
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

            print(type(event.Sid))

            

            response = chat_with_ollama(log)
            
            pymsgbox.alert(f"""
                Sumnjiv događaj detektovan:
                Event ID: {event.EventID}
                Event Category: {event.EventCategory}
                Event Type: {event.EventType}
                Computer Name: {event.ComputerName}
                Hostname: {hostname}
                IP Address: {ip_address}
                Source: {event.SourceName}
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
                Ollama: {response}
            """, "WARNING!")
            
    # Close log
    win32evtlog.CloseEventLog(hand)

# Initialize chat with ollama 
def chat_with_ollama(prompt):
    try:
        # Create a chat with ollama with chosen model
        response = ollama.chat(model="dolphin-mistral", messages=[{"role": "user", "content": prompt}])
        return response["message"]["content"] if "message" in response and "content" in response["message"] else "No response from Ollama."
    except Exception as e:
        return f"Error: {e}"

# Main
if __name__ == '__main__':
    while True:
        get_recent_windows_logs('Application', minutes=0.205)  
        time.sleep(12)
