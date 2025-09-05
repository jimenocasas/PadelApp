
from crypto import Crypto

"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `user.py` maneja la gestión de usuarios, incluyendo el registro, 
autenticación y verificación de nombres de usuario.
"""
class Message:

    def __init__(self, db_connection):
        self.conn = db_connection
        self.cursor = self.conn.cursor()
        self.crypto = Crypto(self.conn)

    def send_message(self, sender, receiver, message, password):
        if not sender == receiver:
            message_receiver = self.crypto.encrypt_message_rsa(receiver,
                                                              message, password)

            message_sender = self.crypto.encrypt_message_rsa(sender,
                                                             message, password)

            signature = self.crypto.sign_message(message, sender, password)
            if message_receiver:
                self.cursor.execute('''
                INSERT INTO messages (sender, receiver, message_receiver,
                message_sender, hmac_tag_receiver, hmac_tag_sender, salt_autentication_receiver, 
                salt_autentication_sender, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (sender, receiver, message_receiver[0], message_sender[
                    0], message_receiver[1], message_sender[1],
                      message_receiver[2], message_sender[2], signature))
                self.conn.commit()
            else:
                return -1
        else:
            return -2


    def get_messages_receiver(self, receiver):
        self.cursor.execute('SELECT * FROM messages WHERE receiver = ?', (receiver,))
        messages = self.cursor.fetchall()
        return messages

    def get_messages_sender(self, sender):
        self.cursor.execute('SELECT * FROM messages WHERE sender = ?', (sender,))
        messages = self.cursor.fetchall()
        return messages
