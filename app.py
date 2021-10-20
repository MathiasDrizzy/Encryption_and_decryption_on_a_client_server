import pyDH,os,logging
from flask import Flask, request
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES

app = Flask(__name__)

#Desactivate log messages
log = logging.getLogger('werkzeug')
log.disabled = True

#Diffie Hellman
@app.get('/getpubkey/')
def key():
    d1 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    d1_sharedkey = d1.gen_shared_key(int(request.get_data()))
    sharedKey = d1_sharedkey
    print(f'the synchronized key is: {d1_sharedkey}')
    return str(d1_pubkey)

#DES NUNCE
@app.get('/getNunce/')
def N():
    global Nonce
    Nonce = request.get_data()
    print('Nonce received', Nonce)
    return 'Nonce received ' + str(Nonce)

#DES MSG
@app.get("/getMSG/")
def getMessage():
    global file1
    Messagee = request.get_data()
    cipher = DES.new(b'-8B key-', DES.MODE_EAX, Nonce)
    Decrypt = cipher.decrypt(Messagee)
    WriteMessage = os.getcwd() + str('\\mensajerecibido.txt')
    file1 = open(WriteMessage, "w")
    line = str('Decrypted message with DES:  ')+ str(Decrypt.decode("utf-8")) + str(" \n")
    file1.write(line)
    print('DES Decrypt done, it has been written to the txt file: mensajerecibido')
    return 'DES Decrypt done, it has been written to the txt file: mensajerecibido'


#3DES KEY
@app.get('/getKey/')
def KEY():
    global key
    key = request.get_data()
    print('Key received', key)
    return 'Key received ' + str(key)


#3DES NUNCE
@app.get('/getNunce2/')
def N2():
    global Nonce2
    Nonce2 = request.get_data()
    print('Nonce received', Nonce2)
    return 'Nonce received ' + str(Nonce2)

#3DES MSG
@app.get("/getMSG2/")
def getMessage2():
    Messagee = request.get_data()
    cipher = DES3.new(key, DES.MODE_EAX, Nonce2)
    Decrypt = cipher.decrypt(Messagee)
    line = str('Decrypted message with 3DES: ')+str(Decrypt.decode("utf-8")) + str(" \n")
    file1.write(line)
    print('3DES Decrypt done, it has been written to the txt file: mensajerecibido')
    return '3DES Decrypt done, it has been written to the txt file: mensajerecibido'

#AES KEY
@app.get('/getKey2/')
def KEY2():
    global key2
    key2 = request.get_data()
    print('Key received', key2)
    return 'Key received ' + str(key2)

#AES Nunce
@app.get('/getNunce3/')
def N3():
    global Nonce3
    Nonce3 = request.get_data()
    print('Nonce3 received', Nonce3)
    return 'Nonce3 received ' + str(Nonce3)

#AES Tag
@app.get("/getTag/")
def getTag():
    global tag
    tag = request.get_data()
    print(tag)
    print(type(tag))
    print('Tag received', tag)
    return 'Tag received ' + str(Nonce3)


#AES MSG
@app.get("/getMSG3/")
def getMessage3():
    Messagee = request.get_data()
    cipher = AES.new(key2, DES.MODE_EAX, Nonce3)
    Decrypt = cipher.decrypt(Messagee)
    try:
        cipher.verify(tag)
        line = str('Decrypted message with AES:  ') + str(Decrypt.decode("utf-8")) + str(" \n")
        file1.write(line)
        file1.close()
        print('AES Decrypt done, it has been written to the txt file: mensajerecibido')

        return 'AES Decrypt done, it has been written to the txt file: mensajerecibido'

    except:
        file1.close()
        print('----Error Tag----')
        return '----Error Tag----'

if __name__ == "__main__":
    app.run()
