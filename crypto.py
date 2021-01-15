
def encrypt(text, password):
    encrypted = ''
    for i, char in enumerate(text):
        print(str(ord(char)) + '  ' + str(ord(password[i % len(password)])))
        encrypted += chr(ord(char) * ord(password[i % len(password)]))
    return encrypted


def decrypt(text, password):
    decrypted = ''
    for i, char in enumerate(text):
        print(str(ord(char)) + '  ' + str(ord(password[i % len(password)])))
        decrypted += chr(int(ord(char) / ord(password[i % len(password)])))
    return decrypted



def get_key():
    import hashlib, os
    from getpass import getpass
    password = getpass("Enter password : ")
    input2 = getpass("Verify password : ")
    if password == input2:
        import os
        salt = b'A\xcd\x9eiy\x05\xe2\x99\xf6tU\xf3I\x86L\xd7\t\xf2r\xa1\x88\x9di\xd6\xcf\xd3\xc25G\x9f\xaf\xff'
        key = hashlib.pbkdf2_hmac(
            'sha256',  # The hash digest algorithm for HMAC
            password.encode('utf-8'),  # Convert the password to bytes
            salt,  # Provide the salt
            100000  # It is recommended to use at least 100,000 iterations of SHA-256
        )
    else:
        raise Exception
    return key

import argparse
import os
import struct
import random
from Crypto.Cipher import AES


def encrypt_file(in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.
        key:
            The encryption key - a bytes object that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.
        in_filename:
            Name of the input file
        out_filename:
            If None, '<in_filename>.enc' will be used.
        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    key=get_key()
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
    return out_filename


def decrypt_file(in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    key=get_key()
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    print(out_filename)
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
    return out_filename

decrypt_file('../btc_wallet_info.enc')