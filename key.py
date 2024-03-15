from cryptography.fernet import Fernet
 
cipher_key = Fernet.generate_key()
with open("key.txt", "wb") as f:
    f.write(cipher_key)