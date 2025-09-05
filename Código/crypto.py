from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `crypto.py` proporciona funciones criptográficas para el cifrado y
descifrado de mensajes, así como para la autenticación de los mismos.
"""

class Crypto:
    def __init__(self, db_connection):
        self.conn = db_connection
        self.cursor = self.conn.cursor()
        self.private_key = None

    # Generar claves RSA: returnamos la clave pública en formto PEM y la
    # clave privada sin cifrar
    def generate_rsa_keys(self,):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_pem

    #Serializar clave pública
    def serialize_public_key(self, public_key):
        public_key = serialization.load_pem_public_key(public_key.encode())
        return public_key

    # Insertar claves en la base de datos
    def insert_keys(self,username, password):
        self.private_key, self.public_key = self.generate_rsa_keys()
        self.crypted_private_key = self.cipher_private_key(self.private_key,
                                                     password)
        self.cursor.execute(
            '''UPDATE users SET public_key = ?, private_key = ? WHERE username = ?''',
            (self.public_key.decode(), self.crypted_private_key, username))
        self.conn.commit()

    # Cifrar clave privada con la misma contraseña que se usa para registrarse
    def cipher_private_key(self, private_key, password):
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return encrypted_private_key

    # Cifrar la tarjeta de crédito para almacenarla en la base de datos
    def cipher_credit_card(self, credit_card, public_key):

        encrypted_credit_card = public_key.encrypt(
            credit_card.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_credit_card

    # Descifrar clave privada
    def decipher_private_key(self, encrypted_private_key, password):
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_private_key,
                password=password.encode()
            )
            return private_key
        except ValueError:
            return None

    #Metodos de autenticación de mensajes
    def generate_hmac_key(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    def create_hmac(self, key, message):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()

    def verify_hmac(self, key, message, tag):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        try:
            h.verify(tag)
            return True
        except InvalidSignature:
            return False

    def encrypt_message_rsa(self, user, message, password):
        self.cursor.execute('SELECT public_key FROM users WHERE username = ?',
                            (user,))
        public_key = self.cursor.fetchone()[0]
        public_key = serialization.load_pem_public_key(public_key.encode())

        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        key, salt = self.generate_hmac_key(password)
        hmac_tag = self.create_hmac(key, ciphertext)

        # Log the algorithm and key length
        print(f"Mensaje cifrado usando RSA con longitud de clave "
              f"{public_key.key_size} bits y padding OAEP. Para el usuario {user}")
        print(f"Autenticado y verificado con el algoritmo: HMAC-SHA256, "
              f"Longitud de la clave:"
              f" {len(key) * 8} bits")

        return ciphertext, hmac_tag, salt

    def decrypt_rsa(self, user, ciphertext, password, hmac_tag, salt):

        self.cursor.execute('SELECT private_key FROM users WHERE username = '
                            '?', (user,))
        private_key = self.cursor.fetchone()[0]
        decrypt_private_key = self.decipher_private_key(private_key, password)

        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).derive(password.encode())

        if not self.verify_hmac(key, ciphertext, hmac_tag):
            raise ValueError("HMAC verification failed")

        plaintext = decrypt_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Mensaje descifrado usando RSA con longitud de clave "
              f"{decrypt_private_key.key_size} bits y padding OAEP. Para el usuario {user}")
        print(f"Autenticado y verificado con el algoritmo: HMAC-SHA256, "
              f"Longitud de la clave:"
              f" {len(key) * 8} bits")
        return plaintext.decode()


    '''PRÁCTICA 1 - PARTE 2(FIRMA DIGITAL Y DESPLIEGUE PKI)'''

    # Firmar mensaje
    def sign_message(self, message, sender, password):

        self.cursor.execute('SELECT private_key FROM users WHERE username = ?',
                            (sender,))
        cipher_private_key = self.cursor.fetchone()[0]
        uncipher_private_key = self.decipher_private_key(cipher_private_key,
                                                          password)


        signature = uncipher_private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Firma generada con éxito. Con el algoritmo: RSASSA-PSS, longitud de clave: 2048 bits")
        return signature

    # Verificar firma

    def verify_signature(self, message, signature, public_key):
        try:
           #sccdemos al certificadpo del usuario
           #luego hacemos el
           # publickey.verify
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Firma verificada con éxito.")
            return True
        except InvalidSignature:
            print("Firma no válida.")
            return False


    # Cifrar las claves privadas de las autoridades para los certificados

