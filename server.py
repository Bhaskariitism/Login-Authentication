#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 17 09:23:32 2023
Server side code for PKL file
@author: bhaskarbiswas
"""

import socket
import pickle

def receive_pickle_file():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5000))  # Change to appropriate host and port
    server_socket.listen(1)

    print("Server listening...")
    client_socket, client_address = server_socket.accept()

    received_data = b""
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        received_data += data

    # Deserialize the received pickle data
    received_object = pickle.loads(received_data)

    with open('received_data.pkl', 'wb') as file:
        file.write(received_data)

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    receive_pickle_file()
