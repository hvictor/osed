#!/usr/bin/env python3

import socket
import sys

def main():
    # Ensure proper usage
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <port> <file_path>")
        sys.exit(1)

    try:
        # Parse command-line arguments
        port = int(sys.argv[1])
        file_path = sys.argv[2]

        # Load the file content as bytes
        with open(file_path, "rb") as file:
            data = file.read()

        # Create the server socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(("", port))  # Bind to all available interfaces
            server_socket.listen(1)  # Listen for a single incoming connection
            print(f"Listening on port {port}...")

            # Accept a connection
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connection received from {addr}")

                # Send the data
                conn.sendall(data)
                print("Data sent successfully.")
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
    except ValueError:
        print("Error: Port must be an integer.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
