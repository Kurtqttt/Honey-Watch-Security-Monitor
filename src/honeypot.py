
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

HOST = "127.0.0.1"
PORT = 2222
LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "events.jsonl"


def log_event(event):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def main():
    print("HoneyWatch honeypot starting...")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Logging events to: {LOG_FILE}")
    print("Press Ctrl+C to stop.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        while True:
            connection, address = server.accept()

            with connection:
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": address[0],
                    "source_port": address[1],
                    "destination_port": PORT,
                    "event_type": "connection_attempt",
                    "service": "SSH-like decoy",
                }

                log_event(event)
                print(json.dumps(event, indent=2))

                connection.sendall(
                    b"HoneyWatch decoy service. Connection logged.\n"
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nHoneyWatch stopped.")
    except OSError as error:
        print(f"Socket error: {error}")