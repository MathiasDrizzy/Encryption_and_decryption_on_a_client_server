import pyDH,requests,os, time
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def getPath():
    global A
    temp = time.time()
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    A = os.chdir(dname)
    Mensaje = os.getcwd() + str('\\mensajeentrada.txt')
    with open(Mensaje) as f:
        lines = f.readlines()
        for i in lines:
            A = i


def DiffieRun():
    d2 = pyDH.DiffieHellman()  # We generate the diffie helman key from the client
    d2_pubkey = d2.gen_public_key()
    response = requests.get(f'http://127.0.0.1:5000/getpubkey',data=str(d2_pubkey))
    d2_sharedkey = d2.gen_shared_key(int(response.text))
    print(f'the synchronized key is: {d2_sharedkey}')


def DESRun():
    global plaintext
    key = b'-8B key-'
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    plaintext = bytes(A, encoding='utf-8')
    msg = cipher.encrypt(plaintext)
    response1 = requests.get(f'http://127.0.0.1:5000/getNunce', data=nonce)
    response2 = requests.get("http://127.0.0.1:5000/getMSG", data=msg)
    print(response1.text)
    print(response2.text)

def ThreeDESRun():
    key = DES3.adjust_key_parity(get_random_bytes(24))
    print(key)
    cipher = DES3.new(key, DES3.MODE_EAX)
    msg = cipher.encrypt(plaintext)
    nonce = cipher.nonce
    response3 = requests.get(f'http://127.0.0.1:5000/getKey', data=key)
    response4 = requests.get(f'http://127.0.0.1:5000/getNunce2', data=nonce)
    response5 = requests.get("http://127.0.0.1:5000/getMSG2", data=msg)
    print(response3.text)
    print(response4.text)
    print(response5.text)

def AESRun():
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    msg,tag= cipher.encrypt_and_digest(plaintext)
    print(tag)
    print(type(tag))
    response6 = requests.get(f'http://127.0.0.1:5000/getKey2', data=key)
    response7 = requests.get(f'http://127.0.0.1:5000/getNunce3', data=nonce)
    response8 = requests.get("http://127.0.0.1:5000/getTag", data=tag)
    response9 = requests.get("http://127.0.0.1:5000/getMSG3", data=msg)
    print(response6.text)
    print(response7.text)
    print(response8.text)
    print(response9.text)





if __name__ == "__main__":
    getPath()
    DiffieRun()
    DESRun()
    ThreeDESRun()
    AESRun()

# https://github.com/amiralis/pyDH
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/des.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
# https://jumpshare.com/v/NOhvEsUIfLIurnsTtuS0
# https://jumpshare.com/v/KG6jJYrGTcPCfocMLXXT
