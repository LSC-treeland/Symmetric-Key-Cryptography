from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from os.path import exists
import time
import sys

class Encryptor:
    def __init__(self, key):
        self.key = key


    # AES-256
    # key:16bytes
    # iv:16bytes  
    def CBC_encrypt(self, plainText, mode, key):
        cipher = AES.new(key, AES.MODE_CBC)

        cipherText = cipher.encrypt(pad(plainText, AES.block_size))

        return cipher.iv + cipherText


    def CBC_decrypt(self, cipherText, mode, key):
        ivLen = AES.block_size

        iv = cipherText[:ivLen]

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        plainText = unpad(cipher.decrypt(cipherText[ivLen:]), AES.block_size)
        
        return plainText
        
        
    # AES-256
    # key:16bytes
    # nonce:8bytes      
    def CTR_encrypt(self, plainText, mode, key):
        cipher = AES.new(key, AES.MODE_CTR)
        
        cipherText = cipher.encrypt(pad(plainText, AES.block_size))

        return cipher.nonce + cipherText


    def CTR_decrypt(self, cipherText, mode, key):
        nonceLen = AES.block_size // 2
    
        nonce = cipherText[:nonceLen]
        
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        
        plainText = unpad(cipher.decrypt(cipherText[nonceLen:]), AES.block_size)
        
        return plainText
 
 
    # ChaCha20
    # key:32byte
    # nonce:8bytes   
    def ChaCha20_encrypt(self, plainText, key):
        cipher = ChaCha20.new(key=key)
        
        cipherText = cipher.encrypt(plainText)        

        return cipher.nonce + cipherText
     
        
    def ChaCha20_decrypt(self, cipherText, key):
        nonce = cipherText[:8]
        
        cipher = ChaCha20.new(key=key, nonce=nonce)
        
        plaintext = cipher.decrypt(cipherText[8:])
        
        return plaintext
        
        
    def encrypt_file(self, file_name, mode):
        with open(file_name, 'rb') as f:
            plainText = f.read()
            
        if mode == "CBC":
            encFile = self.CBC_encrypt(plainText, mode, self.key)
        elif mode == "CTR":
            encFile = self.CTR_encrypt(plainText, mode, self.key)
        elif mode == "ChaCha20":
            encFile = self.ChaCha20_encrypt(plainText, self.key)  
                      
        with open(file_name + ".enc", 'wb') as f:
            f.write(encFile)
        print("encrypt_file_name: " + file_name + ".enc")
        # os.remove(file_name)


    def decrypt_file(self, file_name, mode):
        with open(file_name, 'rb') as f:
            cipherText = f.read()
            
        if mode == "CBC":
            decFile = self.CBC_decrypt(cipherText, mode, self.key)
        elif mode == "CTR":
            decFile = self.CTR_decrypt(cipherText, mode, self.key)
        elif mode == "ChaCha20":
            decFile = self.ChaCha20_decrypt(cipherText, self.key)
            
        with open( mode + "_" + file_name[:-4], 'wb') as f:
            f.write(decFile)
        print("decrypt_file_name: " + mode + "_" + file_name[:-4])
        #os.remove(file_name)


print("Executing...")

while True:
    file_name = "EncryFile.zip"   
    if len(sys.argv) == 2:
        file_name = sys.argv[1]
    if(exists(file_name) == False):
        print(file_name, " not exist")
        exit();
    print("+----------+")
    print("|1.AES_CBC |")
    print("|2.AES_CTR |")
    print("|3.ChaCha20|")
    print("|4.EXIT    |")
    print("+----------+")
    
    choice = int(input())

    start = time.time()
    if choice == 1:
        CBC_key = Random.get_random_bytes(16)
        enc = Encryptor(CBC_key)
        enc.encrypt_file(file_name,"CBC")
        enc.decrypt_file(file_name + ".enc","CBC")
        
    elif choice == 2:
        CTR_key = Random.get_random_bytes(16)
        enc = Encryptor(CTR_key)
        enc.encrypt_file(file_name,"CTR")
        enc.decrypt_file(file_name + ".enc","CTR")
        
    elif choice == 3:
        ChaCha20_key = Random.get_random_bytes(32)
        enc = Encryptor(ChaCha20_key)
        enc.encrypt_file(file_name,"ChaCha20")
        enc.decrypt_file(file_name + ".enc","ChaCha20")
        
    elif choice == 4:
        exit()
        
    else:
        print("Invalid option!")
        
    end = time.time()
    print("Executing time", round(end - start, 3), "secs")
    print()
