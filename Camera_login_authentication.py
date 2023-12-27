# -*- coding: utf-8 -*-
"""
Created on Mon Dec 25 22:32:07 2023
Camera login authentication
@author: HP
"""

import hashlib
import pickle
import crypto
import sys
sys.modules['Crypto'] = crypto
from Crypto.Random.random import getrandbits


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


