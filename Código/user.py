
import sqlite3
import os
import re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `user.py` maneja la gestión de usuarios, incluyendo el registro, 
autenticación y verificación de nombres de usuario.
"""

class User:
    def __init__(self, db_connection):
        self.conn = db_connection
        self.cursor = self.conn.cursor()

    def register_user(self, username, nombre, apellido1, apellido2, zona, email,
                      phone, password):
        # Comprobar que la contraseña es segura
        try:
            if zona.lower() not in ['madrid norte', 'madrid sur']:
                raise ValueError("La zona no es válida.")

            if phone:
                if not phone.isdigit() or len(phone) != 9:
                    raise ValueError(
                        "El formato del número de teléfono no es válido")

            if len(password) < 8:
                raise ValueError(
                    "La contraseña debe tener al menos 8 caracteres.")
            if not any(char.isdigit() for char in password):
                raise ValueError(
                    "La contraseña debe contener al menos un dígito.")
            if not any(char.isupper() for char in password):
                raise ValueError(
                    "La contraseña debe contener al menos una letra mayúscula.")
            if not any(char.islower() for char in password):
                raise ValueError(
                    "La contraseña debe contener al menos una letra minúscula.")
            symbols = [
                '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',',
                '-', '.', '/',
                ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_',
                '`', '{', '|', '}', '~'
            ]
            if not any(char in symbols for char in password):
                raise ValueError(
                    "La contraseña debe contener al menos un símbolo.")

            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            if not re.match(email_regex, email):
                raise ValueError(
                    "El formato del correo electrónico no es válido")

        except ValueError as e:
            print(e)
            return -1

        # añadir salt a la contraseña
        salt = self.generate_salt()
        password = self.hash_password(password, salt)

        try:
            # Insertar el usuario y la contraseña hasheada en la base de datos

            self.cursor.execute('''INSERT INTO users (username, nombre, 
            apellido1,
                            apellido2, zona, email, phone, password, salt, public_key, private_key) 
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                           (username, nombre, apellido1, apellido2,zona, email,
                            phone,
                            password, salt, 'None', 'None'))
            self.conn.commit()
            print(f"Usuario {username} registrado con éxito.")

            return 0


        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed: users.username' in str(e):
                print(f"El usuario {username} ya existe.")

            elif 'UNIQUE constraint failed: users.email' in str(e):
                print(f"El correo electrónico {email} ya está registrado.")
            else:
                print("Error al registrar el usuario.")

        return -1

    def sing_in(self):
        username = input("Ingrese el nombre de usuario: ")
        password = input("Ingrese la contraseña: ")
        self.authenticate_user(username, password)

    def authenticate_user(self, username, password):
        self.cursor.execute('SELECT password, salt FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        if result:
            stored_password, stored_salt = result
            hashed_password = self.hash_password(password, stored_salt)
            if hashed_password == stored_password:
                print("Autenticación exitosa.")
                return True
            else:
                print("Contraseña incorrecta.")
                return False
        else:
            print("Usuario no encontrado.")
            return False

    def check_username(self, username):
        self.cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        return result is not None

    def get_public_key(self, username):
        self.cursor.execute('SELECT public_key FROM users WHERE username = ?',
                            (username,))
        public_key = self.cursor.fetchone()[0]
        return public_key

    def hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def generate_salt(self):
        return os.urandom(16)

    def get_zona_user(self, username):
        self.cursor.execute('SELECT zona FROM users WHERE username = ?',
                            (username,))
        zona = self.cursor.fetchone()[0]
        return zona

    def get_encrypted_private_key(self, username):
        self.cursor.execute('SELECT private_key FROM users WHERE username = ?',
                            (username,))
        private_key = self.cursor.fetchone()[0]
        return private_key
