
"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `dataBase.py` gestiona la conexión y las operaciones con la base de
 datos, incluyendo la inserción, actualización y consulta de datos.
"""
class dataBase:

    def __init__(self, db_connection):
        self.conn = db_connection
        self.cursor = self.conn.cursor()

    #Creamos las tablas de la base de datos
    def create_table(self):

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            nombre TEXT NOT NULL,
                            apellido1 TEXT NOT NULL,
                            apellido2 TEXT NOT NULL,
                            zona TEXT NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            phone TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            public_key TEXT,
                            private_key TEXT)''')
        self.conn.commit()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS reservations (
                            username TEXT NOT NULL,
                            time TEXT NOT NULL,
                            court TEXT NOT NULL,
                            credit_card TEXT NOT NULL)''')
        self.conn.commit()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                            sender TEXT NOT NULL,
                            receiver TEXT NOT NULL,
                            message_receiver TEXT NOT NULL,
                            message_sender TEXT NOT NULL,
                            hmac_tag_receiver TEXT NOT NULL,
                            hmac_tag_sender TEXT NOT NULL,
                            salt_autentication_receiver TEXT NOT NULL,
                            salt_autentication_sender TEXT NOT NULL,
                            signature TEXT NOT NULL)''')
        self.conn.commit()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                            username TEXT NOT NULL,
                            autority TEXT NOT NULL,
                            private_key TEXT,
                            certificate TEXT NOT NULL)''')

    #Métodos para trabajar con la base de datos
    def execute(self, query, values):

        self.cursor.execute(query, values)
        self.conn.commit()

    def fetchone(self, query, values):

        self.cursor.execute(query, values)
        return self.cursor.fetchone()

    def close(self):

        self.conn.close()


