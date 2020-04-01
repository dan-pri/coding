from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
secret_code = "P@ssw0rd"

#Schlüsselpaar generieren
keyPair = RSA.generate(1024)
#Public Key erstellen
pubKey = keyPair.publickey()

#öffentlichen Schlüssel exportieren
pubKeyPem = pubKey.exportKey(format='PEM')
save_pub = open("pub.pem", "wb")
save_pub.write(pubKeyPem)
save_pub.close()

#privaten Schlüssel exportieren
prvKeyPem = keyPair.exportKey(format='PEM',passphrase = secret_code,pkcs = 1)
save_prv = open("prv.pem", "wb")
save_prv.write(prvKeyPem)
save_prv.close()


#öffentlichen Schlüssel importieren
read_pub = open("pub.pem", "rb")
pub_key_imp = RSA.import_key(read_pub.read())

#privaten Schlüssel importieren
read_prv = open("prv.pem", "rb")
prv_key_imp = RSA.import_key(read_prv.read(),passphrase = secret_code)


#Nachricht encoden
message = "Diese Nachricht ist geheim"
message = message.encode()

#Nachricht verschlüsseln
cipher = PKCS1_OAEP.new(pub_key_imp)
encrypted = cipher.encrypt(message)
print("Verschlüsselt: " + encrypted.hex())

#Nachricht entschlüsseln
cipher1 = PKCS1_OAEP.new(prv_key_imp)
message = cipher1.decrypt(encrypted)
message = message.decode()
print("Entschlüsselt: " + str(message))

