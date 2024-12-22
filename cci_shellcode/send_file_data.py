#!/usr/bin/env python3

import socket
import sys

def main():
    # Ensure a file is provided as a command-line argument
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <ip> <file_path>")
        sys.exit(1)

    file_path = sys.argv[2]

    # Configure the IP address and port
    ip = sys.argv[1]
    port = 9001

    try:
        # Load the file content as bytes
        with open(file_path, "rb") as file:
            data = file.read()

        # Create the socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # Connect to the server
                s.connect((ip, port))

                # Send the data
                s.sendall(data)
                print("Data sent successfully.")
            except Exception as e:
                print(f"Error while sending data: {e}")
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
