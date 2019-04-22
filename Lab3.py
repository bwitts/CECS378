# STEP 1
# You will write a script that looks for a pair of RSA Public and private key (using a
# CONSTANT file path; PEM format). If the files does not exist (use OS package) 
# then generate the RSA public and private key (2048 bits length) using the same
# constant file path.

from os import path
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric, hashes
from Lab2 import MyFileEncryptionMAC, MyFileDecryptMAC

# Key Generation
def generateKeyPair():
    #generate private key
    privateKey = rsa.generate_private_key(public_exponent = 65537, 
        # By using anything other than 65537 you reduce the compatibility w/ existing 
        # hardware/software, and break conformance to some standards of security.
        # Higher e - makes public RSA operation slower but it is safer for padding
        # Lower e - makes operation faster
        key_size=2048, # number of bits long the key should be, larger = more security
        backend=default_backend())

    publicKey = privateKey.public_key() # generate public key

    return publicKey, privateKey

def keyValidation():
    # If there are NO key.PEM created yet, create a new set of keys and store it in the directory "keys"
    if(os.path.exists('./Keys/publicKey.pem') == False):
        # generate a public and private key using the generate function but not .PEM file yet
        publicKey, privateKey = generateKeyPair()

    # Creating the privateKey.PEM file format - base64 format w/ delimiters
    # Using private_bytes() to serialize the key that we've generated without having to encrypt
        privatePem = privateKey.private_bytes(
            encoding = serialization.Encoding.PEM, #PEM - encapsulation format, the key type can be of any type
            format = serialization.PrivateFormat.TraditionalOpenSSL, #An enumeration for private key formats. Inputs the -----BEGIN RSA PRIVATE KEY----- in the PEM file
            encryption_algorithm = serialization.NoEncryption()) #Serialize w/o encryption

        # Creating the publicKey.PEM file, serialize the public key using public_bytes
        publicPem = publicKey.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo #typical public key format. It consists of an algorithm identifier and the public key as a bit string. Choose this unless you have specific needs.
        )

        # Making a folder/directory called "keys" to store both private/public keys
        os.makedirs('./Keys')
        privateFile = open ("Keys/privateKey.pem", "wb")  
        privateFile.write(privatePem) # Write private keys to file
        privateFile.close()
        publicFile = open ("Keys/publicKey.pem", "wb") 
        publicFile.write(publicPem) # Writes public keys to file
        publicFile.close()
        print("Private Key & Public Key are created.")
        
#STEP 2
# Create the method (RSACipher, C, IV, tag, ext) = MyRSAEncrypt(filepath, RSA_Publickey_filepath):
# In this method, you first call MyfileEncryptMAC (filepath) which will return (C, IV, tag, Enckey, HMACKey, ext). You
# then will initialize an RSA public key encryption object and load pem publickey from the RSA_publickey_filepath. 
# Lastly, you encrypt the key variable ("key"= EncKey+ HMACKey (concatenated)) using the RSA publickey in OAEP padding mode.
# The result will be RSACipher. You then return (RSACipher, C, IV, ext). Remember to do the inverse
# (MyRSADecrypt (RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath)) which does the exactly inverse of the above
# and generate the decrypted file using your previous decryption methods.

def MyRSAencrypt(filepath, RSA_Publickey_filepath):
    # call encryption 
    C, IV, tag, EncKey, HMACKey, ext  = MyFileEncryptionMAC(filepath)

    # load public key from file
    # initialize an RSA public_key encryption object and load pem publickey from the RSA_publickey_filepath
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key( 
            key_file.read(), # read PEM encoded key data
            backend = default_backend())

    # encrypt the public key
    RSACipher = public_key.encrypt(
            EncKey + HMACKey,
            asymmetric.padding.OAEP(mgf = asymmetric.padding.MGF1( #OAEP padding, mgf - A mask generation function, takes a hash algorithm
                    algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(), label = None))

    return RSACipher, C, IV, ext, tag

def MyRSAdecrypt(filepath, RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):

    # Open the the private key .PEM file 
    with open(RSA_Privatekey_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key( 
            key_file.read(),
            password = None, #shouldnt require a password if the private key wasn't encrypted
            backend = default_backend())

    # use the private key to decrypt and obtain concatenated key of EncKey and HMACKey
    key = private_key.decrypt(      
            RSACipher,
            asymmetric.padding.OAEP(
                    mgf = asymmetric.padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None))

    # Deconcatenating the keys
    # first 32 bytes are enc key 
    EncKey = key[:32]

    # last 32 byets are hmac key
    HMACKey = key[-32:]

    # Decrypt and obtain the m (plaintext)
    m = MyFileDecryptMAC(filepath, IV, EncKey, ext, tag, HMACKey)
    return m

#----------------------------------Testing-------------------------------------
print("Encrypting image.jpg")
keyValidation()
file_path = path.abspath("image.jpg")
RSACipher, C, IV, ext, tag = MyRSAencrypt(file_path, "Keys/publicKey.pem")
dec_file_path_input = input("What is the name of the file you wish to decrypt: ")
MyRSAdecrypt(dec_file_path_input+ext, RSACipher, C, IV, tag, ext, "Keys/privateKey.pem")