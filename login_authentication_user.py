#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug 13 08:37:06 2023

@author: bhaskarbiswas
"""
import socket
import re
import hashlib
import json
import pickle
import crypto
import sys
sys.modules['Crypto'] = crypto
from Crypto.Random.random import getrandbits
from tkinter import*
from tkinter import messagebox
#----FUNCTIONS---------#
""" ************* FUNCTIONS ****************"""
"""HASH CALCULATION"""
def calculate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

"""XOR OF STRINGS"""
def xor_strings(str1, str2):
    # Convert the input strings to bytes
    bytes1 = bytes(str1, 'utf-8')
    bytes2 = bytes(str2, 'utf-8')
    
    # Perform XOR on each corresponding byte and create a new bytes object
    xor_result = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])
    
    # Convert the result bytes back to a string
    xor_string = xor_result
   
    return xor_string

"""STRING TO HASH CONVERTION"""
def string_to_hex(input_string):
    # Convert the input string to bytes using UTF-8 encoding
    bytes_data = input_string.encode('utf-8')
    
    # Convert the bytes to a hexadecimal representation
    hex_representation = bytes_data.hex()
    
    return hex_representation

"""JSON FILE READ"""
def get_value_from_file(filename, key):
    with open(filename, "r") as file:
        data = json.load(file)
        if key in data:
            return data[key]
        else:
            return None
"""READ DATA FROM PKL FILE"""

        
"""ASCII TO UNICODE """
def convert_ascii_to_unicode(ascii_string):
    # Use regular expressions to find all occurrences of \xNN
    ascii_escape_regex = re.compile(r'\\x([0-9a-fA-F]{2})')
    
    # Replace \xNN occurrences with \u00NN (Unicode escape)
    unicode_string = ascii_escape_regex.sub(lambda match: f'\\u00{match.group(1)}', ascii_string)
    
    return unicode_string  
#---load values from server-----#
with open('registration.pkl', 'rb') as file:
    loaded_data = pickle.load(file)
    
#----------SERVER PART----------#
def receive_pickle_file():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))  # Change to appropriate host and port
    server_socket.listen(1)

    print("Server listening...")
    client_socket, client_address = server_socket.accept()

    with open('received_file.pkl', 'wb') as file:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file.write(data)

    client_socket.close()
    server_socket.close()
#---------CLIENT PART-----------#
def send_pickle_file(filename):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))  # Change to appropriate host and port

    with open(filename, 'rb') as file:
        data = file.read(1024)
        while data:
            client_socket.send(data)
            data = file.read(1024)

    client_socket.close()
#-------user interface----------#

root = Tk()
root.maxsize(width = 750, height = 450)
root.minsize(width = 500, height = 300)
root.title("LOGIN AUTHENTICATION AND SESSION KEY")

#------ USER LOGIN PHASE-------#
def login_authentication():
    
    try:
        ID_i1 = tb2.get('0.0',END)
        tb2.delete('0.0',END)
        PW_i1 = tb3.get('0.0',END)
        tb3.delete('0.0',END)

        ID_i1 = string_to_hex(ID_i1)
        PW_i1 = string_to_hex(PW_i1)
        Ki_last = calculate_sha256_hash(ID_i1+PW_i1)
        UAi = loaded_data['UAi']
        print(UAi)
        K_i = xor_strings(UAi.decode('utf-8'), Ki_last)
        K_i1 = K_i.decode('utf-8')
        IDi = loaded_data['IDi']
        UID_i = K_i1+IDi
        UID_i = calculate_sha256_hash(K_i1+ID_i1)

        UIDi = loaded_data['UIDi']
        TCi = loaded_data['TCi']
        RID_i_last = calculate_sha256_hash(UID_i+TCi)

        Ai = loaded_data['Ai']
        RID_i = xor_strings(Ai, RID_i_last)
        RID_i1 = RID_i.decode('utf-8')
        Bi = loaded_data['Bi']
        SBI_i_last =  calculate_sha256_hash(RID_i1+TCi)
        SBI_i = xor_strings(Bi,SBI_i_last)

        SB_i1 = SBI_i.decode('utf-8')
        RPWi = loaded_data['RPWi']
        UF_i = calculate_sha256_hash(RID_i1+RPWi+SB_i1)
        UFi = loaded_data['UFi']
        if UF_i== UFi:
            SBi = loaded_data['SBi']
            RIDi = loaded_data['RIDi']
            K_z = calculate_sha256_hash(SBi+RIDi)
            Ei = loaded_data['Ei']
            K_z1 = xor_strings(Ei,K_z)
            K_z11 = K_z1.decode('utf-8')
            Kz = loaded_data['Kz']
            ID_z = calculate_sha256_hash(Kz+RID_i1)
            Gi = loaded_data['Gi']
            ID_z1 = xor_strings(Gi,ID_z)
            ID_zi1 = ID_z1.decode('utf-8')
            IDz = loaded_data['IDz']
            CID_z = calculate_sha256_hash(IDz+Kz)
            C_i_last =calculate_sha256_hash(SB_i1+TCi)
            Di = loaded_data['Di']
            C_i = xor_strings(Di,C_i_last)
            C_i1 = C_i.decode('utf-8')
            
            CIDz = loaded_data['CIDz']
            Ci = loaded_data['Ci']
            RID_z = calculate_sha256_hash(CIDz+Ci)
            ri = hex(getrandbits(64))
            M1_last = calculate_sha256_hash(Ci+TCi)
            M1 = xor_strings(ri, M1_last)
            M1 = M1.decode('utf-8')
            M2_last = calculate_sha256_hash(ri+TCi)
            M2 = xor_strings(IDi, M2_last)
            M2 = M2.decode('utf-8')
            Ti = hex(5)
            RIDz = loaded_data['RIDz']
            M3 = calculate_sha256_hash(IDi+ri+RIDi+RIDz+Ti)
            Siz = calculate_sha256_hash(SBi+IDz)
            M4_last = calculate_sha256_hash(Siz+TCi+Ti)
            M4 = xor_strings(Kz, M4_last)
            print("USER SIDE COMPUTATION DONE")
            
            print("M1:- ", hex(M1))
            print("M2:- ", M2)
            print("M3:- ", M3)
            print("M4:- ", M4)
            print("TCi:- ", TCi)
            print("Ti:- ", Ti)
        else:
            print("INVALID USER")
            
        #---SERVER SIDE COMPUTATION------------#
        T_i = hex(10)

        if (5 - 2<=3):
            Xj = loaded_data['Xj']
            C_i = calculate_sha256_hash(Xj+TCi)
            r_i_last = calculate_sha256_hash(C_i+TCi)
            r_ii = xor_strings(M1,r_i_last)
            
            r_i = r_ii.decode('utf-8')
            Kj = loaded_data['Kj']
            USN_1 = calculate_sha256_hash(ID_i1+Kj)
            M_3 = calculate_sha256_hash(ID_i1+ri+RIDi+RIDz+Ti)
            if(M_3==M3):
                rj = hex(getrandbits(64))
                M5_last = calculate_sha256_hash(RIDz+TCi)
                M5 = xor_strings(rj, M5_last)
                M6 = calculate_sha256_hash(RIDz+ri+rj)
            else:
                print("Mismatch found")
                        
            
            print("M4:- ", M4)
            print("M5:- ", M5)
            print("TCi:- ", TCi)
            #print("Tj:- ", Tj)
            print("Ti:- ", Ti)
            print("USER VALID")
        else:
            print("INVALID USER")


        #-----------CAMERA LOGIN PHASE-------------#
        T_j = hex(10)

        if (10-5<=5):
            
            K_z111_last = calculate_sha256_hash(Siz+TCi+Ti)
            K_z2 = xor_strings(M4.decode('utf-8'), K_z111_last)
            K_z2 = K_z2.decode('utf-8')
            CID_z1 = calculate_sha256_hash(IDz+K_z2)
            C_i11_last = calculate_sha256_hash(CID_z1+TCi)
            Fi = loaded_data['Fi']
            C_i11 = xor_strings(Fi.decode('utf-8'),C_i11_last)
            C_i11 = C_i11.decode('utf-8')
            RID_z1 = calculate_sha256_hash(CID_z1+C_i11)
            r_j_last = calculate_sha256_hash(RID_z1+TCi) 
            r_j = xor_strings(M5.decode('utf-8'),r_j_last)
            r_j = r_j.decode('utf-8')
            r_i1_last = calculate_sha256_hash(C_i11+TCi)
            r_i1 = xor_strings(M1,r_i1_last)
            r_i1 = r_i1.decode('utf-8')
            M_6 = calculate_sha256_hash(RID_z1+r_i1+r_j)
            if(M6 == M_6):
                rz = hex(getrandbits(64))
                SKijz = calculate_sha256_hash(r_i1+r_j+rz+RIDz+TCi)
                print("Session Key camera:", SKijz)
                M7_last = calculate_sha256_hash(RIDz+rj+ri)
                M7 = xor_strings(rz,M7_last)
                M7 = M7.decode('utf-8')
                M8_last = calculate_sha256_hash(CIDz+SBi+ri)
                M8 = xor_strings(rz, M8_last)
                M8 = M8.decode('utf-8')
                M9 = calculate_sha256_hash(RIDz+ri+rj+rz+TCi+SKijz)
                print("VALID CAMERA")
            else:
                
                print("M7:- ", M7)
                print("M8:- ", M8)
                print("M9:- ", M9)
                #print("Tz:- ", Tz)
                
                print("INVALID CAMERA")
        else:
            print("INVALID CAMERA")

            
            
        #------SERVER CAMERA AUTHENTICATION------#

        T_z = hex(10)
        if(10-5<=5):
            r_z_last = calculate_sha256_hash(RIDz+rj+r_i1)
            r_z = xor_strings(M7, r_z_last)
            r_z = r_z.decode('utf-8')
            SK_ijz = calculate_sha256_hash(r_i1+r_j+rz+RIDz+TCi)
            print("Session key server:-", SK_ijz)
            M_9 = calculate_sha256_hash(RIDz+r_i1+rj+r_z+TCi+SK_ijz)
            if(M_9 == M9):
                
                print("VALID CAMERA SERVER")
            else:
                print("INVALID CAMERA SERVER")
            
            print("M5:- ", M5)
            print("M8:- ", M8)
            print("M9:- ", M9)
            #print("Tj1:- ", Tj1)
        else:
            print("INVALID")
        #-----SERVER USER LAST SECTION ------#

        T_j1 = hex(10)
        if(10-5<=5):
            r_z1_last = calculate_sha256_hash(CIDz+SBi+ri)
            r_z1 = xor_strings(M8, r_z1_last)
            r_z1 = r_z1.decode('utf-8')
            r_j1_last = calculate_sha256_hash(RID_z+TCi)
            r_j1 = xor_strings(M5.decode('utf-8'), r_j1_last)
            r_j1 = r_j1.decode('utf-8')
            SK_ijz1 = calculate_sha256_hash(r_i1+r_j1+rz+RIDz+TCi)
            print("Session key user:- ", SK_ijz1)
            M_91 = calculate_sha256_hash(RID_z1+r_i1+rj+r_z1+TCi+SK_ijz1)
            if(M_91 == M9):
                print("Valid camera data")
            else:
                print("Invalid camera data")
        else:
            print("INVALID")   
        messagebox.showinfo("LOGIN AUTHENTICATION","LOGIN AUTHENTICATION SUCCESSFUL")
        if SKijz == SK_ijz and SKijz == SK_ijz1:
            print("SESSION KEY ESTABLISHED")
            messagebox.showinfo("SESSION KEY", "VALID SESSION")
        else:
            print("INVALID SESSION")
            messagebox.showinfo("SESSION KEY", "INVALID SESSION")
    except :
        messagebox.showinfo("LOGIN AUTHENTICATION", "INVALID USER AND CAMERA")


lb1=Label(root,text="LOGIN AUTHENTICATION ",width=20,border=2)
lb1.place(x=150,y=30)

# User Input ID&Password
lb2=Label(root,text="Enter User ID",width=20,border=2)
lb2.place(x=10,y=60)
tb2=Text(root,width=20,height=1.5,border=2)
tb2.place(x=190,y=65)
#
lb3=Label(root,text="Enter Password",width=20,border=2)
lb3.place(x=10,y=130)
tb3=Text(root,width=20,height=1.5,border=2)
tb3.place(x=190,y=130)


butn3=Button(root,text="Login",padx=20,pady=5,command=login_authentication)

butn3.place(x=200,y=200)


root.mainloop()        




  
 