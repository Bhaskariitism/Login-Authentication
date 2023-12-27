#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug 13 08:36:25 2023
USER AND CAMERA REGISTRATION PHASE
@author: bhaskarbiswas
"""

import re
import hashlib
import json
import pickle
import crypto
import sys
import socket
sys.modules['Crypto'] = crypto
from Crypto.Random.random import getrandbits
from tkinter import*
from tkinter import messagebox
import socket
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

"""USER INTERFACE"""
global tb
root= Tk()
root.maxsize(width=500,height=300)
root.minsize(width=500,height=300)
root.title("USER AND CAMERA REGISTRATION")


#-------SEND FILE TO SERVER---------#
def send_pickle_file(filename):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 5000))  # Change to appropriate host and port

    with open(filename, 'rb') as file:
        data = file.read()

    # Serialize the data using pickle
    serialized_data = pickle.dumps(data)

    client_socket.sendall(serialized_data)
    client_socket.close()

#----------MAIN FUNCTION------------#    

def registration_phase():
    global tb
    
    try:
        #----USER REGISTRATION------#
                
        ID = tb2.get('0.0',END)
        tb2.delete('0.0',END)
        PW = tb3.get('0.0',END)
        tb3.delete('0.0',END)
        
        #PW = tb3
        #ID = 'pramod'
        #PW = 'pramod@924'
        print("ID:- ",hex(ID))
        print("PW:- ", hex(PW))
        IDi = string_to_hex(ID)
        PWi = string_to_hex(PW)
        Ki = hex(getrandbits(64))
        UIDi  = Ki+IDi
        UIDi = calculate_sha256_hash(UIDi)
        print("IDi:- ", hex(IDi))
        print("PWi:- ", hex(PWi))
        print("UIDi:- ", hex(UIDi))
        print("Ki:-" , Ki)
            
        #---------FOR CAMERA REGISTRATION-----------#
              
        IDz = "usercamera"
        IDz = string_to_hex(IDz)
        Kz = hex(getrandbits(64))
        CIDz  = IDz+Kz
                
        CIDz = calculate_sha256_hash(CIDz)
                
        print("CIDz:- ",CIDz)
        print("IDz:- ",IDz)
        print("Kz:- ", Kz)

        #--------FOR SERVR COMPUTAION------------------#
        Kj = hex(getrandbits(224))
        X = hex(getrandbits(224))
        Xj = calculate_sha256_hash(Kj+X)
        print("Kj:- ", Kj)
        print("X:- ",X)
        print("Xj:- ",Xj)
                
        RIDi = xor_strings(UIDi, Kj)
        print("RIDi:- ", hex(RIDi))
                
        RIDi = calculate_sha256_hash(RIDi.decode('utf-8'))
        print("RIDi_hash:- ", RIDi)

        SBi = xor_strings(UIDi, X)
        SBi = calculate_sha256_hash(SBi.decode('utf-8'))
        print("SBi:- ", SBi)

        TCi = hex(10)

        Ci = Xj+TCi
        Ci = calculate_sha256_hash(Ci)
        print("Ci:- ", Ci)

        RIDz =calculate_sha256_hash(CIDz+Ci)
        print("RIDz:- ", RIDz)
        Ai_last = calculate_sha256_hash(UIDi+TCi)
        Ai = xor_strings(RIDi, Ai_last)
        Ai = Ai.decode('utf-8')
        print("Ai:- ",Ai)
        Bi_last = calculate_sha256_hash(RIDi+TCi)
        Bi = xor_strings(SBi, Bi_last)
        Bi = Bi.decode('utf-8')
        print("Bi:- ",Bi)
        Di_first = calculate_sha256_hash(SBi+TCi)
        Di = xor_strings(Di_first, Ci)
        Di = Di.decode('utf-8')
        print("Di:- ",Di)

        Siz = calculate_sha256_hash(SBi+IDz)
        print("Siz:- ", Siz)

        Fi_last = calculate_sha256_hash(CIDz+TCi)
        Fi = xor_strings(Ci, Fi_last)
        print("Fi:- ", Fi)

        PIDi = RIDi+RIDz+calculate_sha256_hash(Xj)
        print("PIDi:- ", PIDi)
        USNi = calculate_sha256_hash(IDi+Kj)
        print("USNi:- ", USNi)

        #--------USER REGISTRATION PART II---------#

        RPWi = calculate_sha256_hash(PWi+Ki)
        print("RPWi:- ", RPWi)

        UAi_last = calculate_sha256_hash(IDi+PWi)
        UAi = xor_strings(Ki, UAi_last) 
        UAi1 = UAi.decode('utf-8')
        print("UAi:- ", UAi1)

        Ei_last = calculate_sha256_hash(SBi+RIDi)
        Ei = xor_strings(Kz, Ei_last)
        Ei = Ei.decode('utf-8')
        print("Ei:- ", Ei)

        Gi_last = calculate_sha256_hash(Kz+RIDi)
        Gi = xor_strings(IDz, Gi_last)
        Gi = Gi.decode('utf-8')
        print("Gi:- ",Gi)

        UFi = calculate_sha256_hash(RIDi+RPWi+SBi)
        print("UFi:- " , UFi) 


        data = {
            "UAi":UAi,
            "IDi":IDi,
            "UIDi":UIDi,
            "TCi":TCi,
            "Bi":Bi,
            "RPWi":RPWi,
            "UFi": UFi,
            "Ai": Ai,
            "SBi":SBi,
            "RIDi":RIDi,
            "Ei":Ei,
            "Kz":Kz,
            "Gi":Gi,
            "Di":Di,
            "IDz":IDz,
            "Ci":Ci,
            "CIDz":CIDz,
            "RIDz":RIDz,
            "Xj":Xj,
            "Kj":Kj,
            "Fi":Fi
            
        }

        with open('registration.pkl', 'wb') as file:
            pickle.dump(data, file)
        #send_pickle_file('registration.pkl')
        print("USER REGISTRATION SUCCESSFUL")
        #send_pickle_file('/Users/bhaskarbiswas/Downloads/HC_code/registration.pkl')
        #messagebox.showinfo("USER REGISTRATION", "FILES SENT TO SERVER ")
        messagebox.showinfo("USER REGISTRATION","USER AND CAMERA REGISTRATION SUCCESSFUL")

        
    except :
        print("REGISTRATION FAILED")
        messagebox.showinfo("USER REGISTRATION","REGISTRATION UNSUCCESSFUL")
        



lb1=Label(root,text="USER REGISTRATION",width=20,border=2)
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
#tb3 = Tk.Entry(root, show="*")

butn3=Button(root,text="Submit",padx=20,pady=5,command=registration_phase)

butn3.place(x=200,y=200)


root.mainloop()
        
    
      
