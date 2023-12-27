# -*- coding: utf-8 -*-
"""
Created on Sat Dec 23 21:41:26 2023

CAMERA SERVER REGISTRATION phase

@author: HP
"""


import hashlib
import pickle
import crypto
import sys
sys.modules['Crypto'] = crypto
from Crypto.Random.random import getrandbits
import time

'''parameter k_s, k_j, IDSC_j,  random number r_j, IDH_j = hash(xor(ID_j,r_j), M_j = hash(xor(IDH_j, K_s)))
Store IDH_j, IDSC_j, K_j, M_j ''' 

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


K_s = hex(getrandbits(32))
K_j = hex(getrandbits(32))
IDSC_j = hex(getrandbits(32))
ID_j = hex(getrandbits(32))
r_j = hex(getrandbits(32))
IDH_j =calculate_sha256_hash( xor_strings(ID_j,r_j).hex())
M_j = calculate_sha256_hash( xor_strings(IDH_j,K_s).hex())


print('Secret Key:-',K_s)
print('Encryption Key:-',K_j)
print('Pseudo identity:-',IDSC_j)
print('Identity:-',ID_j)
print('Random number:-',r_j)
print('IDH_j:-',IDH_j)
print('M_j:-',M_j)


data = {
     'K_s':K_s, 'K_j':K_j, 'IDSC_j': IDSC_j, 'ID_j': ID_j, 'r_j':r_j, 'IDH_j':IDH_j, 'M_j': M_j
     
 }

with open('registration.pkl', 'wb') as file:
     pickle.dump(data, file)

'''Login authentication phase'''

t_j1 = time.time()

r_j1 = hex(getrandbits(128))
L_j = xor_strings(r_j1, calculate_sha256_hash(IDSC_j + K_j))


'''Server session'''
t_j2 = time.time()
delt = 300
if((t_j2 - t_j1)>delt):
    print("Session time out")
else:
    M_j1 = calculate_sha256_hash(xor_strings(IDH_j, K_s).hex())
    if(M_j1!=M_j):
        print('REject the session')
    else:
        r_j1 = xor_strings(L_j, calculate_sha256_hash(IDSC_j+K_j)).hex()
        if(Tag3 != tag4):
            print('Session rejected')
        else:
            T_sc = time.time()
            r_j2 = hex(getrandbits(128))
            Q_j = xor_strings(r_j2, calculate_sha256_hash(hex(int(T_sc)) + K_j + IDSC_j + r_j1))
            A_j = calculate_sha256_hash(IDSC_j + T_sc + r_j1 + r_j2)
            data = {'IDSC_j': IDSC_j, 'IDSC_j': C14, 'K_j': K_j, 'K_jnew': C15, 'K'}



''' Camera side'''

t_sc1 = time.time()

if((t_sc1 - T_sc) > delt ):
    print('Timed out')
else: 
    if(c_12 != C_16):
        print('Timed out')
    else:
        r_j22 = xor_strings(Q_j, calculate_sha256_hash(T_sc + K_j + IDSC_j + r_j1)).hex()
        A_j = calculate_sha256_hash(IDSC_j + T_sc + r_j1 + r_j22)
        if (A_j != A_j):
            print('Session timed out')
        else: 
            data = {'IDSC_j': C10, 'K_j' : C11, 'SK_SCj': C9}
        
         



    


