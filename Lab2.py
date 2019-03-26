from os import urandom
from os import path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

#magic numbers
IV_SIZE = 16
KEY_SIZE = 32
PADDING_SIZE = 128

#Generate a 16 byte IV, and encrypt the message using the key and IV in CBC mode (AES).
#Return an error if the len(key) < 32 (i.e., the key has to be 32 bytes = 256 bits).
def myEncryptMAC(message, encKey, HMACKey):
    #frist check for key length
    if len(encKey) < KEY_SIZE:
        return "Invalid key length."
    try:
        #encode message to binary raw data
        message = message.encode()
    except:
        pass

    #initilize 16 bytes IV with secure crytography random generator in os
    IV = urandom(IV_SIZE)

    #initialize padder with PKCS7
    padder = padding.PKCS7(PADDING_SIZE).padder()
    #pad the message and save it
    padd_data = padder.update(message) + padder.finalize()
    message = padd_data

    #setting up AES in CBC mode
    cipher = Cipher((algorithms.AES(encKey)), modes.CBC(IV), backend=default_backend())

    #generate encryptor object
    encryptor = cipher.encryptor()

    #generating cipher text
    C = encryptor.update(message) + encryptor.finalize()

    #Generate Tag with HMAC
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C) #add the tag to cipher text

    #Finalize the current context and return the message as bytes
    tag = h.finalize()

    return (C, IV, tag)

#let's decrypt
def myDecryptMAC(C, IV, encKey, tag, HMACKey):

    #Verify Tag-use HMAC to verify integrity & authenticity of the message
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())

    #hash and authenticates bytes
    h.update(C)

    #Compares bytes to current digest (cryptographic hash function containing a string of digits)
    #Finalize the current context and securely compare digest to signature
    h.verify(tag)

    #set the cipher to AES, CBC with default backend
    cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())

    #generate decryptor object
    decryptor = cipher.decryptor()

    #get the message and decrypt it
    dm = decryptor.update(C) + decryptor.finalize()

    #now lets unpadd
    try:
        unpadder=padding.PKCS7(PADDING_SIZE).unpadder()
        dm=unpadder.update(dm) +unpadder.finalize()
        return dm
    except:
        return dm

#file encryption algorithm
def MyFileEncryptionMAC(filepath):
    #generate a 32 bit key for file encryption
    encKey = urandom(KEY_SIZE)

    #generate a 32 bit key for HMAC verification
    HMACKey = urandom(KEY_SIZE)

    #open and read the file as single string (becomes message)
    with open (filepath,'rb') as f:
        data = f.read()

    #pass the string to myEncrypt and save the cipher
    result = myEncryptMAC(data, encKey, HMACKey)

    #split the path into root and extexntion so that root+ext=filepath
    extention=path.splitext(filepath)[1]

    #add key and extention to result
    result += (encKey, HMACKey, extention)

    #output ciphered filepath
    input_en_filepath = input("Enter a file name for encrypted file output: ")

    #create a writable image
    image_result = open(input_en_filepath+extention, 'wb')

    #write the decoding result
    image_result.write(result[0])
    return result

#file decryption algorithm
def MyFileDecryptMAC(encrypted_filepath, IV, encKey, extention, tag, HMACKey):
    #read the encrypted file and put it in data
    with open(encrypted_filepath, 'rb') as f:
        data = f.read()

    #set the decryption file path
    input_dec_filepath=input("Enter a file name for decrypted file output: ")

    file_name = input_dec_filepath + extention
    plaintext = myDecryptMAC(data, IV, encKey, tag, HMACKey)

    #create a writable image nad write the decoding result
    image_result=open(file_name,'wb')
    image_result.write(plaintext)

#-------------------------------------------------------------------------------------
#Testing
file_path = path.abspath("image.jpg")
ct, iv, tag, encKey, HMACKey, ext = MyFileEncryptionMAC(file_path)
input_enc_filepath = input("Enter the file name for the previously encrypted file: ")
MyFileDecryptMAC(input_enc_filepath+ext, iv, encKey, ext, tag, HMACKey)
