from tkinter import simpledialog

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateBuilder, random_serial_number
from cryptography.x509.oid import NameOID
import datetime
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.hazmat.primitives import serialization
import os
from crypto import Crypto
from user import User

class Certificate:
    def __init__(self, db_connection):
        self.conn = db_connection
        self.cursor = self.conn.cursor()
        self.crypto = Crypto(db_connection)
        self.user = User(db_connection)

    def
        (self):
        # Generar clave privada para AC1
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        autority = "Autoridad certificadora raiz"
        root_name = "Comunidad de Madrid (AC1)"

        # Crear un nombre para el certificado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Comunidad de Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Padel Comunidad de Madrid"),
            x509.NameAttribute(NameOID.COMMON_NAME, root_name),
        ])

        # Crear el certificado autofirmado
        cert = CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # El certificado será válido por 10 años
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        # aqui se pide la contraseña maestra por pantalla
        master_password = simpledialog.askstring("Contraseña Maestra",
                                                 "Introduce la contraseña maestra:\n",
                                                 show='*')

        return private_key, cert_pem, autority, root_name, master_password

    def generate_subordinate_cert(self, ac1_private_key, ac1_cert,
                                  subordinate_name):

        ac1_cert = x509.load_pem_x509_certificate(ac1_cert)


        # Generar clave privada para la autoridad subordinada
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        autority = "Autoridad subordinada"

        # Crear una solicitud de firma de certificado (CSR)
        csr = CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Comunidad de Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Padel Comunidad de Madrid"),
            x509.NameAttribute(NameOID.COMMON_NAME, subordinate_name),
        ])).sign(private_key, hashes.SHA256())

        # Firmar el CSR con la clave privada de AC1
        cert = CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ac1_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        ).sign(ac1_private_key, hashes.SHA256())


        cert_pem = cert.public_bytes(serialization.Encoding.PEM)


        return private_key, cert_pem, autority, subordinate_name

    def generate_user_cert(self, sub_private_key, sub_cert, user_name, user_private_key):

        # Deserialize the subordinate certificate from PEM format
        sub_cert = x509.load_pem_x509_certificate(sub_cert)

        autority = "Persona"
        # Crear una solicitud de firma de certificado (CSR)
        csr = CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Comunidad de Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Padel Comunidad de Madrid"),
            x509.NameAttribute(NameOID.COMMON_NAME, user_name),
        ])).sign(user_private_key, hashes.SHA256())

        # Firmar el CSR con la clave privada de la autoridad subordinada
        cert = CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            sub_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(sub_private_key, hashes.SHA256())

        # Serializar el certificado
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        return cert_pem, autority, user_name

    def save_certificate(self, user_name, autority, private_key,
                         certificate, master_password):


        if private_key != "NO APLICABLE":
            # Cifrar la clave privada
            private_key= self.crypto.cipher_private_key(private_key,
                                                                master_password)
        self.cursor.execute('''INSERT INTO certificates (username, autority, private_key, certificate) 
                            VALUES (?,?,?,?)''',
                            (user_name, autority, private_key, certificate))
        self.conn.commit()
        print(f"Certificado de {user_name} registrado con éxito.")
        return 0

    def create_initial_certificates(self):

        self.cursor.execute(
            '''SELECT COUNT(*) FROM certificates WHERE username = ?''',
            ("Comunidad de Madrid (AC1)",))
        if self.cursor.fetchone()[0] > 0:
            return

        tuple_root = self.generate_self_signed_cert()
        self.save_certificate(tuple_root[3], tuple_root[2], tuple_root[0],
                              tuple_root[1], tuple_root[4])
        tuple_sub_norte= self.generate_subordinate_cert(tuple_root[0],
                                                        tuple_root[1],
                                                        "Madrid Norte ("
                                                        "AC2)")
        self.save_certificate(tuple_sub_norte[3], tuple_sub_norte[2],
                              tuple_sub_norte[0], tuple_sub_norte[1], tuple_root[4])
        tuple_sub_sur = self.generate_subordinate_cert(tuple_root[0],
                                                       tuple_root[1],
                                                       "Madrid Sur (AC3)")
        self.save_certificate(tuple_sub_sur[3], tuple_sub_sur[2],
                              tuple_sub_sur[0], tuple_sub_sur[1], tuple_root[4])

    def is_user_certified(self, user_name):
        self.cursor.execute('''SELECT * FROM certificates WHERE username = ?''', (user_name,))
        if self.cursor.fetchone() is not None:
            return True
        else:
            return False

    def apply_certificate_norte(self, username,private_key_user):
        self.cursor.execute('''SELECT certificate FROM certificates WHERE username = "Madrid Norte (AC2)"''')
        result = self.cursor.fetchone()
        certificate = result[0]
        self.cursor.execute('''SELECT private_key FROM certificates WHERE username = "Madrid Norte (AC2)"''')
        private_key_norte = self.cursor.fetchone()[0]
        #desciframos la clave privada de la entidad subordinada
        master_password = simpledialog.askstring("Solicitud de "
                                                 "certificado Madrid "
                                                 "Norte",
                                                 f"Introduzca la contraseña "
                                                 f"maestra para que "
                                                 f"{username} obtenga el "
                                                 f"certificado de Madrid "
                                                 f"Norte:\n",
                                                 show='*')
        private_key_norte_correcto = self.crypto.decipher_private_key(
            private_key_norte, master_password)

        while private_key_norte_correcto is None:
            master_password = simpledialog.askstring("Solicitud de "
                                                     "certificado Madrid "
                                                     "Norte",
                                                     f"CONTRASEÑA "
                                                     f"INCORRECTA.\n "
                                                     f"Introduzca "
                                                     f"la "
                                                     f"contraseña maestra "
                                                     f"para que {username} "
                                                     f"obtenga el "
                                                     f"certificado de Madrid Norte :\n",
                                                     show='*')

            private_key_norte_correcto = self.crypto.decipher_private_key(
                private_key_norte,
                master_password)

        tuple_user_norte = self.generate_user_cert(private_key_norte_correcto,
                                                 certificate, username,
                                                 private_key_user)

        self.save_certificate(tuple_user_norte[2], tuple_user_norte[1],
                              "NO APLICABLE", tuple_user_norte[0], "None")
        print(f"Certificado de {username} aplicado con éxito.")
        return 0

    def apply_certificate_sur(self, username, private_key_user):
        self.cursor.execute('''SELECT certificate FROM certificates WHERE username = "Madrid Sur (AC3)"''')
        certificate = self.cursor.fetchone()[0]
        self.cursor.execute('''SELECT private_key FROM certificates WHERE username = "Madrid Sur (AC3)"''')
        private_key_sur = self.cursor.fetchone()[0]
        # desciframos la clave privada de la entidad subordinada
        master_password = simpledialog.askstring("Solicitud de "
                                                 "certificado Madrid "
                                                 "Sur",
                                                 f"Introduzca la contraseña "
                                                 f"maestra para que "
                                                 f"{username} obtenga el "
                                                 f"certificado de Madrid Sur:\n",
                                                 show='*')
        private_key_sur_correcto = self.crypto.decipher_private_key(
            private_key_sur,
                                                             master_password)

        while private_key_sur_correcto is None:
            master_password = simpledialog.askstring("Solicitud de "
                                                     "certificado Madrid "
                                                     "Sur",
                                                     f"CONTRASEÑA "
                                                     f"INCORRECTA.\nIntroduzca "
                                                     f"la contraseña maestra para que {username} obtenga el certificado de Madrid Sur:\n",
                                                     show='*')

            private_key_sur_correcto = self.crypto.decipher_private_key(private_key_sur,
                                                               master_password)

        tuple_user_sur = self.generate_user_cert(private_key_sur_correcto, certificate, username,
                                                 private_key_user)

        self.save_certificate(tuple_user_sur[2], tuple_user_sur[1], "NO APLICABLE",
                              tuple_user_sur[0], "None")
        print(f"Certificado de {username} aplicado con éxito.")
        return 0

    def load_certificate(self, cert_pem):
        return x509.load_pem_x509_certificate(cert_pem)

    def verify_certificate(self, public_key_pem, user_name):

        # Deserialize the public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        zona = self.user.get_zona_user(user_name)
        if zona == "Madrid Norte":
            subordinate_cert = self.get_certificate("Madrid Norte (AC2)")

        else:
            subordinate_cert = self.get_certificate("Madrid Sur (AC3)")

        subordinate_public_key = subordinate_cert.public_key()

        self.cursor.execute('''SELECT certificate FROM certificates WHERE username = ?''', (user_name,))
        result = self.cursor.fetchone()
        if result is None:
            return -1

        certificate = result[0]
        certificate = self.load_certificate(certificate)

        #Verificamos que el certificado esta firmado por la autoridad superior
        subordinate_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_algorithm_parameters,
            certificate.signature_hash_algorithm
        )

        cert_public_key = certificate.public_key()

        #Comprobamos que no se ha alterado la clave pública del usuario
        if cert_public_key.public_numbers() == public_key.public_numbers():
            print(f"Certificado de {user_name} verificado con éxito.")
            return 0
        else:
            print(f"Certificado de {user_name} no verificado.")
            return -2


    def get_certificate(self, user_name):
        self.cursor.execute('''SELECT certificate FROM certificates WHERE username = ?''', (user_name,))
        result = self.cursor.fetchone()
        cert = self.load_certificate(result[0])
        if result is None:
            return -1
        return cert
