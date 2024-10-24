import win32.win32evtlog as win32evtlog 
import time
from datetime import datetime, timedelta
import ollama

jedanLog = ""

def get_recent_windows_logs(log_type, minutes):
    # Otvorite log
    hand = win32evtlog.OpenEventLog(None, log_type)

    # Prikupite logove
    total_logs = win32evtlog.GetNumberOfEventLogRecords(hand)

    logs = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)


    cutoff_time = datetime.now() - timedelta(minutes=minutes)

    print(f"Total log records in {log_type} log: {total_logs}")

    for event in logs:
        event_time = event.TimeGenerated
        # Filtrirajte logove prema vremenu
        if event_time >= cutoff_time:
            jedanLog = (f"""
            Event ID: {event.EventID}
            Time Generated: {event.TimeGenerated}
            Source: {event.SourceName}
            Category: {event.EventCategory}
            Description: {event.StringInserts}
            {"-" * 40}
            """)
            response = chat_with_ollama(jedanLog)
            print(f"""
                Event ID: {event.EventID}
                Source: {event.SourceName}
                Time Generated: {event.TimeGenerated}
                Description: {event.StringInserts}
                Ollama: {response}
                """)

    # Zatvorite log
    win32evtlog.CloseEventLog(hand)



def chat_with_ollama(prompt):
    try:
        # Pravilno korišćenje chat funkcije sa modelom "llama2"
        response = ollama.chat(model="deepseek-coder", messages=[{"role": "user", "content": prompt}])
        
        # Logujemo ceo odgovor za debugging
        #print(f"Debug Response: {response}")
        
        # Pristupamo odgovoru unutar message["content"]
        return response["message"]["content"] if "message" in response and "content" in response["message"] else "Nema odgovora od Ollame."
    
    except Exception as e:
        return f"Greška prilikom komunikacije: {e}"

if __name__ == '__main__':
    # firstResponse = chat_with_ollama("I will be sending Windows Event Logs for you to analyze them and tell me if they are potentionally suspicious/risky/malicious or clean/safe, check for suspicious program names, logins... I am a program programmed to send you logs, I wont be able to send you any more information except logs.")
    # print(f"Ollama: {firstResponse}")
    while True:
        get_recent_windows_logs('Application', minutes=0.205)  # Možeš promeniti 'System' u 'Application' ili 'Security'
        
        time.sleep(12)  # Interval u sekundama