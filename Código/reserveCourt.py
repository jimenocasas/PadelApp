
"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `reserveCourt.py` se encarga de la reserva de pistas, verificando
la disponibilidad y la validez de la cuenta bancaria.
"""

from crypto import Crypto

class ReserveCourt:
    def __init__(self, db_connection):
        self.crypto = Crypto(db_connection)
        self.conn = db_connection
        self.cursor = self.conn.cursor()

    def reserve_court(self, username, hora, pista, tarjeta, public_key):

        # Comprobar si el usuario ya ha reservado una pista
        self.cursor.execute('SELECT * FROM reservations WHERE username = ?',
                        (username,))
        if self.cursor.fetchone():
            print("El usuario ya ha reservado una pista.")
            return -1

        # Comprobar si la combinación de hora y pista ya está reservada
        self.cursor.execute('SELECT * FROM reservations WHERE time = ? AND '
                            'court = ?', (hora, pista))
        if self.cursor.fetchone():
            print("La combinación de hora y pista ya está reservada.")
            return -1

        # Comprobar si la cuenta bancaria es válida
        if algoritmo_luhn(tarjeta) != True:
            print("La cuenta bancaria no es válida.")
            return -1

        #Ciframos la tarjeta de crédito para almacenarla en la base de datos
        tarjeta = self.crypto.cipher_credit_card(tarjeta, public_key)

        # Insertar la reserva en la base de datos
        self.cursor.execute('''
        INSERT INTO reservations (username, time, court, credit_card)
        VALUES (?, ?, ?, ?)
        ''', (username, hora, pista, tarjeta))
        self.conn.commit()
        print("Reserva realizada con éxito.")

        return 0

def algoritmo_luhn(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return (checksum % 10 == 0)
