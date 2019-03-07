import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#Generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).
#This function takes in a message that the user wants to encrypt along with a randomly
#generated key. It returns an encrypted message and a randomly generated IV.
def myEncrypt(message, key):
    
    #checking key length, must be 32 bytes
    if len(key) < 32:
        return "Invalid key length."
    else:
        #encode message
        message = message.encode()

    #initilize 16 bytes IV with secure crytography random generator in os
    IV = os.urandom(16)

    #initialize padder with PKCS7
    padder = padding.PKCS7(128).padder()
    
    #pad the message and save it
    pad_data = padder.update(message) + padder.finalize()
    message = pad_data

    #setting up AES in CBC mode
    cipher = Cipher((algorithms.AES(key)), modes.CBC(IV), backend=default_backend())

    #generate an encryptor object
    encryptor = cipher.encryptor()

    #generating cipher text
    C = encryptor.update(message) + encryptor.finalize()
    
    return (C, IV)

#This method takes in a cipher text, an IV, and a key.
def myDecrypt(C, IV, key):
    
    #set the cipher to AES, CBC with default backend
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    
    #generate a decryptor object
    decryptor = cipher.decryptor()

    #get the cipher text and decrypt to plain text
    plainTxt = decryptor.update(C) + decryptor.finalize()

    #start unpadding the plain text to finally return the unpadded message
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plainTxt = unpadder.update(plainTxt) + unpadder.finalize()
        return plainTxt
    except:
        return plainTxt

#testing
key = os.urandom(32) #generate a random 32 bit key
m = "Brittney" #message you want to encypt then decrypt
result = myEncrypt(m, key)
print("Encrypted message: ")
print(result)

print("\nDecrypted message: ")
print(myDecrypt(result[0], result[1], key).decode('utf8'))