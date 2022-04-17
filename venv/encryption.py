from Crypto.Cipher import DES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

def to_do():
    a = input("what do you want to do?\n"
              "1. encryption\n"
              "2. decryption\n")
    if (a == '1'):
        encryption()
    elif (a == '2'):
        decryption()

def encryption():
    plain_text = input("enter your text here: ")
    print("encryption algorithms:\n"
          "1. DES\n"
          "2. AES\n"
          "3. blowfish\n"
          "4. RSA\n"
          "5. "
          "6. "
          "7. "
          "8. "
          "9. "
          "10. ")
    enc_opt = input("choose your encryption algorithm: ")
    if (enc_opt == '1'):
        plain_text = bytes(plain_text,encoding='ascii')
        DES_encryption(plain_text)
        to_do()
    elif(enc_opt=='2'):
        plain_text=bytes(plain_text,encoding='ascii')
        AES_encryption(plain_text)
        to_do()
    elif(enc_opt=='3'):
        plain_text=bytes(plain_text,encoding='ascii')
        blowfish_encryption(plain_text)
        to_do()
    elif(enc_opt=='4'):
        RSA_enc(plain_text)
        to_do()

def DES_encryption(des_data):
    key = b'-8B key-'
    DES_encryption.cipher = DES.new(key, DES.MODE_EAX)
    DES_encryption.msg = DES_encryption.cipher.encrypt(des_data)
    print('your encrypted text is :\n{}'.format(DES_encryption.msg))

def AES_encryption(aes_data):
    key= b'Sixteen byte key'
    AES_encryption.cipher=AES.new(key,AES.MODE_EAX)
    AES_encryption.msg=AES_encryption.cipher.encrypt(aes_data)
    print('your encrypted text is :\n{}'.format(AES_encryption.msg))

def blowfish_encryption(data):
    key = b'An arbitrarily long key'
    blowfish_encryption.cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    blowfish_encryption.msg = blowfish_encryption.cipher.encrypt(data)
    print('your encrypted text is :\n{}'.format(blowfish_encryption.msg))

def RSA_enc(data):
    key = RSA.generate(2048)
    RSA_enc.private_key = key.export_key('PEM')
    public_key = key.publickey().exportKey('PEM')
    message = str.encode(data)
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    RSA_enc.encrypted_text = rsa_public_key.encrypt(message)
    print('your encrypted text is :\n{}'.format(RSA_enc.encrypted_text))

def decryption():
    cipher_text = input("enter your cipher text here: ")
    print("decryption algorithms:\n"
          "1. DES\n"
          "2. AES\n"
          "3. blowfish\n"
          "4. RSA\n"
          "5. "
          "6. "
          "7. "
          "8. "
          "9. "
          "10. ")
    dec_opt = input("choose your decryption algorithm: ")
    if(dec_opt == '1'):
        DES_decryption(cipher_text)
        to_do()
    elif(dec_opt=='2'):
        AES_decryption(cipher_text)
        to_do()
    elif(dec_opt=='3'):
        blowfish_dec(cipher_text)
        to_do()
    elif(dec_opt=='4'):
        RSA_dec(cipher_text)
        to_do()

def DES_decryption(des_cipher):
    key = b'-8B key-'
    d_cipher = DES.new(key, DES.MODE_EAX, DES_encryption.cipher.nonce)
    dec = d_cipher.decrypt(DES_encryption.msg)
    dec=dec.decode('ascii')
    print('your decrypted text is :\n{}'.format(dec))

def AES_decryption(aes_cipher):
    key= b'Sixteen byte key'
    cipher=AES.new(key,AES.MODE_EAX,AES_encryption.cipher.nonce)
    msg=cipher.decrypt(AES_encryption.msg)
    msg=msg.decode('ascii')
    print('your decrypted text is :\n{}'.format(msg))

def blowfish_dec(cipher):
    key = b'An arbitrarily long key'
    cipher=Blowfish.new(key,Blowfish.MODE_EAX,blowfish_encryption.cipher.nonce)
    dec=cipher.decrypt(blowfish_encryption.msg)
    dec=dec.decode('ascii')
    print('your decrypted text is :\n{}'.format(dec))

def RSA_dec(cipher):
    rsa_private_key = RSA.importKey(RSA_enc.private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(RSA_enc.encrypted_text)
    decrypted_text=decrypted_text.decode('ascii')
    print('your decrypted text is :\n{}'.format(decrypted_text))

to_do()