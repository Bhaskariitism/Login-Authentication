# -*- coding: utf-8 -*-
"""
Created on Sat Dec 23 23:44:28 2023
USER SERVER Registration
@author: HP
"""


import hashlib
import pickle
import crypto
import sys
sys.modules['Crypto'] = crypto
from Crypto.Random.random import getrandbits

'''ID_i, r_i, Biometric B_i, UID_i, IDH_i, IDH_i, '''
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
"""STRING PARTITATION"""
def divide_string_in_half(input_string):
    length = len(input_string)
    midpoint = length // 2
    first_half = input_string[:midpoint]
    second_half = input_string[midpoint:]
    return first_half, second_half

ID_i = hex(getrandbits(128))
r_i = hex(getrandbits(128))
B_i = hex(getrandbits(128))
UID_i =calculate_sha256_hash(r_i+ID_i+B_i)
IDH_i = calculate_sha256_hash( xor_strings(ID_i, r_i).hex())



print('ID_i', ID_i)
print('r_i',r_i)
print('B_i', B_i)
print('UID_i', UID_i)
print('IDH_i', IDH_i)

data = {'UID_i':UID_i, 'IDH_i':IDH_i}

with open('USER_REG.pkl', 'wb') as file:
     pickle.dump(data, file)

'''  SERVER SIDE COMPUTATION'''

K_s = hex(getrandbits(128))
K_i = hex(getrandbits(128))
IDU_i = hex(getrandbits(128))
Z_1 = calculate_sha256_hash(xor_strings(IDH_i,K_s ).hex())
Z_11, Z_12 = divide_string_in_half(Z_1)
C_i = xor_strings(Z_11, Z_12).hex()

#data_server = {'':}
print('K_s',K_s)
print('K_i',K_i)
print('IDU_i', IDU_i)
print('Z_1',Z_1)
print('Z_11',Z_11)
print('Z_12',Z_12)
print('C_i', C_i)

PW_i = hex(getrandbits(128))
W_i = xor_strings(calculate_sha256_hash(B_i+ID_i+PW_i),r_i).hex()
Z_2 = calculate_sha256_hash(IDH_i+PW_i)
Z_21, Z_22 = divide_string_in_half(Z_2)

print('PW_i', PW_i)
print('W_i', W_i)
print('Z_2', Z_2)
print('Z_21', Z_21)
print('Z_22', Z_22)



