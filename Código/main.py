
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import sqlite3

from cryptography.hazmat.primitives import serialization

from user import User
from recuperarContraseña import RecuperarContrasena
from dataBase import dataBase
from reserveCourt import ReserveCourt
from crypto import Crypto
from message import Message
from certificate import Certificate

"""
Realizado por Miguel Jimeno Casas y Hector Herraiz Diez en oct 2024
Universidad Carlos III Madrid
Este archivo `main.py` es la aplicación principal que gestiona la interfaz gráfica
 de usuario (GUI) para la autenticación de jugadores de pádel, incluyendo el registro,
  inicio de sesión, recuperación de contraseña, reserva de pistas y envío de mensajes.
"""
class PadelApp:

    # Inicializamos la aplicación y declaramos las variables necesarias
    # dentro de la clase
    def __init__(self, root):
        self.root = root
        self.root.title("Padel Player Authentication")
        self.root.geometry("400x400")
        self.root.configure(bg="#ffffff")
        self.conn = sqlite3.connect('database.db')

        self.global_pin = None
        self.time_var = tk.StringVar()
        self.court_var = tk.StringVar()
        self.username_recover_password = None

        self.char_count_var = tk.StringVar()
        self.char_count_var.set("El mensaje puede tener hasta 100 caracteres")

        self.logged_in_password = None
        self.logged_in_username = tk.StringVar()

        self.crypto = Crypto(self.conn)
        self.user = User(self.conn)
        self.recover = RecuperarContrasena(self.conn)
        self.reserve = ReserveCourt(self.conn)
        self.message = Message(self.conn)
        self.certificate = Certificate(self.conn)

        self.db = dataBase(self.conn)
        self.db.create_table()
        self.certificate.create_initial_certificates()

        self.create_frames()
        self.create_widgets()
        self.show_main()

    # Creamos los frames necesarios para la aplicación
    def create_frames(self):
        self.frame_main = tk.Frame(self.root, bg="#ffffff")
        self.frame_login = tk.Frame(self.root, bg="#ffffff")
        self.frame_register = tk.Frame(self.root, bg="#ffffff")
        self.frame_reserve = tk.Frame(self.root, bg="#ffffff")
        self.frame_recover = tk.Frame(self.root, bg="#ffffff")
        self.frame_verify_pin = tk.Frame(self.root, bg="#ffffff")
        self.frame_new_password = tk.Frame(self.root, bg="#ffffff")
        self.frame_main_log_in = tk.Frame(self.root, bg="#ffffff")
        self.frame_send_message = tk.Frame(self.root, bg="#ffffff")
        self.frame_view_messages_receive = tk.Frame(self.root, bg="#ffffff")
        self.frame_view_messages_sent = tk.Frame(self.root, bg="#ffffff")
        self.frame_select_messages = tk.Frame(self.root, bg="#ffffff")
        self.frame_apply_certificate = tk.Frame(self.root, bg="#ffffff")
        self.frame_applied_certificate_norte = tk.Frame(self.root, bg="#ffffff")
        self.frame_applied_certificate_sur = tk.Frame(self.root, bg="#ffffff")


    # Creamos la interfas de nuestra aplicación
    def create_widgets(self):
        # Frame del menú principal
        self.imagen = Image.open("Código/media/padel.jpg")
        self.photo = ImageTk.PhotoImage(self.imagen)
        tk.Label(self.frame_main, image=self.photo, bg="#ffffff",padx=500).pack(side=tk.RIGHT, padx=1, pady=1)
        tk.Button(self.frame_main, text="Inciar Sesión", command=self.show_login, font=("Arial", 25), bg="#00796b",fg="white", padx=100, pady=5).pack(pady=150, padx=100, anchor='w')
        tk.Button(self.frame_main, text="Registrarse", command=self.show_register, font=("Arial", 25), bg="#004d40", fg="white", padx=100, pady=5).pack(pady=150, padx=100, anchor='w')
        self.frame_main.pack()

        # Frame de inicio de sesión
        tk.Label(self.frame_login, text="Usuario", font=("Arial", 12),
                 bg="#ffffff").pack(pady=5, anchor='center')
        self.entry_username_login = tk.Entry(self.frame_login,
                                             font=("Arial", 12))
        self.entry_username_login.pack(pady=5, anchor='center')

        tk.Label(self.frame_login, text="Contraseña", font=("Arial", 12),
                 bg="#ffffff").pack(pady=5, anchor='center')
        password_frame_login = tk.Frame(self.frame_login)
        password_frame_login.pack(pady=5, anchor='center')
        self.entry_password_login = tk.Entry(password_frame_login, show="*",
                                             font=("Arial", 12))
        self.entry_password_login.pack(side=tk.LEFT)
        btn_toggle_password_login = tk.Button(password_frame_login,
                                              text="Mostrar",
                                              command=lambda: self.toggle_password_visibility(
                                                  self.entry_password_login,
                                                  btn_toggle_password_login),
                                              font=("Arial", 12), bg="#00796b",
                                              fg="white", padx=10, pady=5)
        btn_toggle_password_login.pack(side=tk.LEFT, pady=5, padx=5, ipadx=5)

        tk.Button(self.frame_login, text="Iniciar Sesión",
                  command=self.submit_login, font=("Arial", 12), bg="#00796b",
                  fg="white", padx=10, pady=5).pack(pady=20, anchor='center')
        tk.Button(self.frame_login, text="¿Contraseña Olvidada?",
                  command=self.show_recover, font=("Arial", 12), bg="#fbc02d",
                  fg="white", padx=10, pady=5).pack(pady=5, anchor='center')
        tk.Button(self.frame_login, text="Cancelar", command=self.show_main,
                  font=("Arial", 12), bg="#d32f2f", fg="white", padx=10,
                  pady=5).pack(pady=5, anchor='center')


        # Frame de ventana principal logueado
        button_options = {
            "font": ("Arial", 25),
            "bg": "#00796b",
            "fg": "white",
            "padx": 100,
            "pady": 10,
            "width": 20
        }

        tk.Button(self.frame_main_log_in, text="Reservar Pista",
                  command=self.show_reserve, **button_options).pack(pady=30)

        tk.Button(self.frame_main_log_in, text="Enviar Mensaje",
                  command=self.show_send_message, **button_options).pack(
            pady=30)

        tk.Button(self.frame_main_log_in, text="Ver Mensajes",
                  command=self.show_select_messages, **button_options).pack(
            pady=30)

        tk.Button(self.frame_main_log_in, text="Certificarse",
                  command=self.show_apply_certificate, **button_options).pack(
            pady=30)

        button_options["bg"] = "#d32f2f"
        tk.Button(self.frame_main_log_in, text="Cerrar Sesión",
                  command=self.show_main, **button_options).pack(pady=30)
        button_options["bg"] = "#00796b"


        # Frame de certificación aplicada norte
        tk.Label(self.frame_applied_certificate_norte,
                 text="Tu usuario ya está certificado",
                 font=("Arial", 14, "bold"),
                 bg="#ffffff", fg="black", padx=20, pady=10).pack(pady=30)
        self.certificate_image_norte = Image.open(
            "Código/media/Norte.jpg").resize(
            (600, 400))
        self.certificate_photo_norte = ImageTk.PhotoImage(
            self.certificate_image_norte)
        tk.Label(self.frame_applied_certificate_norte,
                 image=self.certificate_photo_norte,
                 bg="#ffffff").pack(pady=10)
        tk.Button(self.frame_applied_certificate_norte, text="Salir",
                  command=self.show_main_log_in, font=("Arial", 14, "bold"),
                  bg="#d32f2f", fg="white", padx=20, pady=10).pack(pady=30)

        # Frame de certificación aplicada sur
        tk.Label(self.frame_applied_certificate_sur,
                 text="Tu usuario ya está certificado",
                 font=("Arial", 14, "bold"),
                 bg="#ffffff", fg="black", padx=20, pady=10).pack(pady=30)
        self.certificate_image_sur = Image.open("Código/media/Sur.jpg").resize(
            (600, 400))
        self.certificate_photo = ImageTk.PhotoImage(self.certificate_image_sur)
        tk.Label(self.frame_applied_certificate_sur,
                 image=self.certificate_photo,
                 bg="#ffffff").pack(pady=10)
        tk.Button(self.frame_applied_certificate_sur, text="Salir",
                  command=self.show_main_log_in, font=("Arial", 14, "bold"),
                  bg="#d32f2f", fg="white", padx=20, pady=10).pack(pady=30)

    # Frame de solicitud de certificado
        tk.Button(self.frame_apply_certificate, text="Solicitar Certificado de Madrid Norte",
                  command=self.submit_apply_certificate_norte, font=("Arial", 12), bg="#00796b", fg="white",
                  padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_apply_certificate, text="Solicitar Certificado de Madrid Sur",
                  command=self.submit_apply_certificate_sur, font=("Arial", 12), bg="#00796b", fg="white", padx=10,
                  pady=5).pack(pady=20)
        tk.Button(self.frame_apply_certificate, text="Salir", command=self.show_main_log_in, font=("Arial", 12),
                  bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=20)

        # Frame de selección de mensajes
        tk.Button(self.frame_select_messages, text="Ver Mensajes Enviados",
                  command=self.show_view_messages_sent, font=("Arial", 12),
                  bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_select_messages, text="Ver Mensajes Recibidos",
                  command=self.show_view_messages_receive, font=("Arial", 12),
                  bg="#004d40", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_select_messages, text="Volver",
                  command=self.show_main_log_in, font=("Arial", 12),
                  bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=20)


        # Frame de mensajes recibidos
        tk.Label(self.frame_view_messages_receive, text="Mensajes Recibidos",
                 font=("Arial", 16), bg="#e0f7fa").pack(pady=10)
        tk.Button(self.frame_view_messages_receive, text="Volver",
                  command=self.show_select_messages, font=("Arial", 12),
                  bg="#d32f2f", fg="white", padx=10, pady=5).pack(
            side=tk.BOTTOM, pady=20)

        # Frame de mensajes enviados
        tk.Label(self.frame_view_messages_sent, text="Mensajes Enviados",
                 font=("Arial", 16), bg="#e0f7fa").pack(pady=10)
        tk.Button(self.frame_view_messages_sent, text="Volver",
                    command=self.show_select_messages, font=("Arial", 12),
                    bg="#d32f2f", fg="white", padx=10, pady=5).pack(
            side=tk.BOTTOM, pady=20)

        # Frame de envío de mensajes
        vcmd = (self.root.register(self.validate_message_length), '%P')
        tk.Label(self.frame_send_message, text="Destinatario mensaje",font=("Arial", 16), bg="#e0f7fa").pack(pady=10)
        self.entry_username_messagge = tk.Entry(self.frame_send_message,font=("Arial", 12))
        self.entry_username_messagge.pack(pady=5)

        tk.Label(self.frame_send_message, text="Enviar Mensaje",font=("Arial", 16), bg="#e0f7fa").pack(pady=10)
        self.entry_message = tk.StringVar()
        self.entry_message.trace('w', self.limit_message_length)
        self.entry_messagge = tk.Entry(self.frame_send_message,
                                       textvariable=self.entry_message,
                                       font=("Arial", 12),
                                       validate='key',
                                       validatecommand=vcmd)
        self.entry_messagge.pack(pady=20, padx=50)
        self.char_count_label = tk.Label(self.frame_send_message,
                                         textvariable=self.char_count_var,
                                         font=("Arial", 10), bg="#e0f7fa")
        self.char_count_label.pack(pady=5)
        tk.Button(self.frame_send_message, text="Enviar",
                  command=self.submit_send_message, font=("Arial", 12),
                  bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_send_message, text="Cancelar",
                  command=self.show_main_log_in, font=("Arial", 12),
                  bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=5)

        # Frame de registro
        tk.Label(self.frame_register, text="Usuario", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_username_register = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_username_register.pack(pady=5)

        tk.Label(self.frame_register, text="Nombre", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_nombre = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_nombre.pack(pady=5)

        tk.Label(self.frame_register, text="Primer Apellido", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_apellido1 = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_apellido1.pack(pady=5)

        tk.Label(self.frame_register, text="Segundo Apellido", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_apellido2 = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_apellido2.pack(pady=5)

        tk.Label(self.frame_register, text="Zona", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_zona = ttk.Combobox(self.frame_register, font=("Arial", 12), values=["Madrid Norte", "Madrid Sur"])
        self.entry_zona.pack(pady=5)

        tk.Label(self.frame_register, text="Email", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_email = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_email.pack(pady=5)

        tk.Label(self.frame_register, text="Teléfono", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_phone = tk.Entry(self.frame_register, font=("Arial", 12))
        self.entry_phone.pack(pady=5)

        tk.Label(self.frame_register, text="Contraseña", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        password_frame_register = tk.Frame(self.frame_register)
        password_frame_register.pack(pady=5)
        self.entry_password_register = tk.Entry(password_frame_register, show="*", font=("Arial", 12))
        self.entry_password_register.pack(side=tk.LEFT)
        btn_toggle_password_register = tk.Button(password_frame_register, text="Mostrar", command=lambda: self.toggle_password_visibility(self.entry_password_register, btn_toggle_password_register), font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5)
        btn_toggle_password_register.pack(side=tk.LEFT)

        tk.Button(self.frame_register, text="Registrarse", command=self.submit_register, font=("Arial", 12), bg="#004d40", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_register, text="Cancelar", command=self.show_main, font=("Arial", 12), bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=5)



        # Frame de reserva de pista
        tk.Label(self.frame_reserve, text="Reservar Pista", font=("Arial", 16), bg="#e0f7fa").pack(pady=10)
        tk.Label(self.frame_reserve, text="Usuario", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        tk.Entry(self.frame_reserve, textvariable=self.logged_in_username, font=("Arial", 12), state='readonly').pack(pady=5)
        tk.Label(self.frame_reserve, text="Hora", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        time_dropdown = ttk.Combobox(self.frame_reserve, textvariable=self.time_var, font=("Arial", 12))
        time_dropdown['values'] = ["9:00-10:30", "10:30-12:00", "12:00-13:30", "13:30-15:00", "15:00-16:30", "16:30-18:00", "18:00-19:30", "19:30-21:00"]
        time_dropdown.pack(pady=5)
        tk.Label(self.frame_reserve, text="Nº Pista", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        court_dropdown = ttk.Combobox(self.frame_reserve, textvariable=self.court_var, font=("Arial", 12))
        court_dropdown['values'] = [f'Court {i}' for i in range(1, 6)]
        court_dropdown.pack(pady=5)
        tk.Label(self.frame_reserve, text="Tarjeta de crédito", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        self.entry_bank_account = tk.Entry(self.frame_reserve, font=("Arial", 12))
        self.entry_bank_account.pack(pady=5)
        tk.Button(self.frame_reserve, text="Reservar", command=self.submit_reservation, font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_reserve, text="Cancelar", command=self.show_main_log_in, font=("Arial", 12), bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=5)

        # Frame de recuperación de contraseña
        tk.Label(self.frame_recover, text="Teléfono", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_phone_recover = tk.Entry(self.frame_recover, font=("Arial", 12))
        self.entry_phone_recover.pack(pady=5)
        tk.Label(self.frame_recover, text="Usuario", font=("Arial", 12), bg="#ffffff").pack(pady=5)
        self.entry_user_recovery = tk.Entry(self.frame_recover, font=("Arial", 12))
        self.entry_user_recovery.pack(pady=5)

        tk.Button(self.frame_recover, text="Enviar PIN", command=self.submit_recover, font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_recover, text="Cancelar", command=self.show_login, font=("Arial", 12), bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=5)

        # Frame de verificación de PIN
        tk.Label(self.frame_verify_pin, text="PIN", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        self.entry_pin = tk.Entry(self.frame_verify_pin, font=("Arial", 12))
        self.entry_pin.pack(pady=5)

        tk.Button(self.frame_verify_pin, text="Verificar PIN", command=self.verify_pin, font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)
        tk.Button(self.frame_verify_pin, text="Cancelar", command=self.show_recover, font=("Arial", 12), bg="#d32f2f", fg="white", padx=10, pady=5).pack(pady=5)

        # Frame de nueva contraseña
        tk.Label(self.frame_new_password, text="Nueva Contraseña", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        self.entry_new_password = tk.Entry(self.frame_new_password, show="*", font=("Arial", 12))
        self.entry_new_password.pack(pady=5)

        btn_toggle_new_password = tk.Button(self.frame_new_password, text="Mostar", command=lambda: self.toggle_password_visibility(self.entry_new_password, btn_toggle_new_password), font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5)
        btn_toggle_new_password.pack(pady=5)

        tk.Label(self.frame_new_password, text="Confirmar Contraseña", font=("Arial", 12), bg="#e0f7fa").pack(pady=5)
        self.entry_confirm_password = tk.Entry(self.frame_new_password, show="*", font=("Arial", 12))
        self.entry_confirm_password.pack(pady=5)

        btn_toggle_confirm_password = tk.Button(self.frame_new_password, text="Mostrar", command=lambda: self.toggle_password_visibility(self.entry_confirm_password, btn_toggle_confirm_password), font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5)
        btn_toggle_confirm_password.pack(pady=5)

        tk.Button(self.frame_new_password, text="Guardar", command=self.submit_new_password, font=("Arial", 12), bg="#00796b", fg="white", padx=10, pady=5).pack(pady=20)

    #Método para limpiar los datos introducidos al cambiar de frame
    def clear_fields(self):
        # Limpiar campos de login
        self.entry_username_login.delete(0, tk.END)
        self.entry_password_login.delete(0, tk.END)

        # Limpiar campos de registro
        self.entry_username_register.delete(0, tk.END)
        self.entry_nombre.delete(0, tk.END)
        self.entry_apellido1.delete(0, tk.END)
        self.entry_apellido2.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_phone.delete(0, tk.END)
        self.entry_password_register.delete(0, tk.END)

        # Limpiar campos de recuperación
        self.entry_phone_recover.delete(0, tk.END)
        self.entry_user_recovery.delete(0, tk.END)
        self.entry_pin.delete(0, tk.END)
        self.entry_new_password.delete(0, tk.END)
        self.entry_confirm_password.delete(0, tk.END)

        # Limpiar campos de reserva
        self.logged_in_username.set("")
        self.time_var.set("")
        self.court_var.set("")
        self.entry_bank_account.delete(0, tk.END)


    # Método para mostrar u ocultar frames
    def show_main(self):
        self.clear_fields()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_main.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_login(self):
        self.clear_fields()
        self.frame_main.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_login.pack()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_register(self):
        self.clear_fields()
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_register.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()


    def show_reserve(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_reserve.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_recover(self):
        self.clear_fields()
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack()
        self.frame_verify_pin.pack_forget()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_send_message(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_send_message.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()


    def show_verify_pin(self):
        self.clear_fields()
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_new_password(self):
        self.clear_fields()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_main_log_in(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_select_messages(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_select_messages.pack()
        self.frame_view_messages_receive.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()


    def show_view_messages_receive(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_select_messages.pack_forget()
        self.load_messages_receiver()
        self.frame_view_messages_receive.pack()
        self.frame_view_messages_sent.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_view_messages_sent(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.load_messages_sender()
        self.frame_view_messages_sent.pack()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_apply_certificate.pack_forget()
        self.frame_applied_certificate_norte.pack_forget()
        self.frame_applied_certificate_sur.pack_forget()

    def show_apply_certificate(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.frame_recover.pack_forget()
        self.frame_verify_pin.pack_forget()
        self.frame_new_password.pack_forget()
        self.frame_reserve.pack_forget()
        self.frame_send_message.pack_forget()
        self.frame_main_log_in.pack_forget()
        self.frame_select_messages.pack_forget()
        self.frame_view_messages_receive.pack_forget()
        self.frame_view_messages_sent.pack_forget()
        if self.certificate.is_user_certified(self.logged_in_username.get()):
            zona = self.user.get_zona_user(self.logged_in_username.get())
            self.frame_apply_certificate.pack_forget()
            if zona == "Madrid Norte":
                self.frame_applied_certificate_norte.pack()
                self.frame_applied_certificate_sur.pack_forget()
            else:
                self.frame_applied_certificate_sur.pack()
                self.frame_applied_certificate_norte.pack_forget()

        else:
            self.frame_apply_certificate.pack()
            self.frame_applied_certificate_norte.pack_forget()


    # Método para confirmar el login
    def submit_login(self):
        username = self.entry_username_login.get()
        password = self.entry_password_login.get()

        if not username or not password:
            messagebox.showerror("Error", "Ambos campos son obligatorios")
            return

        if self.user.authenticate_user(username, password):
            messagebox.showinfo("Éxito", "Jugador autenticado con éxito")
            self.logged_in_username.set(username)
            self.logged_in_password = password
            self.show_main_log_in()
        else:
            if messagebox.askyesno("Error",
                                   "Autenticación fallida. ¿Desea recuperar su contraseña?"):
                self.show_recover()

    # Método para confirmar el registro
    def submit_register(self):
        username = self.entry_username_register.get()
        nombre = self.entry_nombre.get()
        apellido1 = self.entry_apellido1.get()
        apellido2 = self.entry_apellido2.get()
        zona = self.entry_zona.get()
        email = self.entry_email.get()
        phone = self.entry_phone.get()
        password = self.entry_password_register.get()

        if not all([username, nombre, apellido1,zona, email, phone, password]):
            messagebox.showerror("Error",
                                 "Todos los campos excepto el segundo apellido son obligatorios")
            return

        if self.user.register_user(username, nombre, apellido1, apellido2, zona,
                                   email, phone, password) == -1:
            messagebox.showerror("Error", "Error al registrar el jugador")
        else:
            if self.crypto.insert_keys(username, password) == -1:
                messagebox.showerror("Error", "Error al insertar las claves")
            else:
                messagebox.showinfo("Éxito", "Jugador registrado con éxito")
                self.show_main()

    #Método para confirmar el cambio de contraseña
    def submit_recover(self):
        global global_pin
        phone = self.entry_phone_recover.get()
        username = self.entry_user_recovery.get()
        self.username_recover_password = username

        if not phone:
            messagebox.showerror("Error",
                                 "El número de teléfono es obligatorio")
            return

        if not self.recover.is_phone_registered(phone, username):
            messagebox.showerror("Error",
                                 "Este número de teléfono o el usuario no están registrados o son incorrectos")
            return

        self.global_pin = self.recover.send_sms_with_pin(phone)
        messagebox.showinfo("Éxito", f"PIN de recuperación enviado a {phone}")
        self.show_verify_pin()

    def submit_apply_certificate_norte(self):
        username = self.logged_in_username.get()
        zona = self.user.get_zona_user(username)
        if zona != "Madrid Norte":
            messagebox.showerror("Error", "No puedes solicitar un certificado de Madrid Norte si eres del sur")
            return
        private_key_user = self.user.get_encrypted_private_key(username)
        decrypted_private_key = self.crypto.decipher_private_key(private_key_user, self.logged_in_password)
        if self.certificate.apply_certificate_norte(username, decrypted_private_key) == -1:
            messagebox.showerror("Error", "Error al solicitar el certificado")
        else:
            messagebox.showinfo("Éxito", "Certificado solicitado con éxito")
            self.show_main_log_in()

    def submit_apply_certificate_sur(self):
        username = self.logged_in_username.get()
        zona = self.user.get_zona_user(username)
        if zona != "Madrid Sur":
            messagebox.showerror("Error", "No puedes solicitar un certificado de Madrid Sur si eres del norte")
            return
        private_key_user = self.user.get_encrypted_private_key(username)
        decrypted_private_key = self.crypto.decipher_private_key(private_key_user, self.logged_in_password)
        if self.certificate.apply_certificate_sur(username, decrypted_private_key) == -1:
            messagebox.showerror("Error", "Error al solicitar el certificado")
        else:
            messagebox.showinfo("Éxito", "Certificado solicitado con éxito")
            self.show_main_log_in()

    def verify_pin(self):
        pin = self.entry_pin.get()
        if not pin:
            messagebox.showerror("Error", "El PIN es obligatorio")
            return

        if pin == str(self.global_pin):
            messagebox.showinfo("Éxito", "PIN correcto")
        else:
            messagebox.showerror("Error", "PIN incorrecto")

        self.show_new_password()

    # Método para enviar un mensaje
    def submit_send_message(self):
        receiver = self.entry_username_messagge.get()
        sender = self.logged_in_username.get()
        message = self.entry_messagge.get()

        if not all([receiver, message]):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        if not self.user.check_username(receiver):
            messagebox.showerror("Error", "Nombre de usuario no encontrado")
            return
        public_key_receiver = self.user.get_public_key(receiver)
        public_key_sender = self.user.get_public_key(sender)

        if self.certificate.verify_certificate(public_key_receiver,
                                               receiver) == -1:
            messagebox.showerror("Error", "El usuario al que quieres enviar "
                                          "el mensaje no está certificado, "
                                          "por lo que no se le puede enviar el mensaje")
            return

        if self.certificate.verify_certificate(public_key_sender,
                                               sender) == -1:
            messagebox.showerror("Error", "Debes de estar certificado para enviar mensajes")
            return

        if self.certificate.verify_certificate(public_key_sender,
                                               sender) == -2:
            messagebox.showerror("Error", "Tu clave publica se ha visto "
                                          "alterada")
            return

        if self.certificate.verify_certificate(public_key_receiver,
                                               receiver) == -2:
            messagebox.showerror("Error", "La clave publica del receptor se ha visto "
                                          "alterada")
            return
        
        send_message = self.message.send_message(sender,
                                                 receiver, message, self.logged_in_password)
        if send_message == -1:
            messagebox.showerror("Error", "Error al enviar el mensaje")
        elif send_message == -2:
            messagebox.showerror("Error",
                                 "No se puede enviar un mensaje a uno mismo")
        elif send_message == -3:
            messagebox.showerror("Error",
                                 "El usuario al que envías el mensaje no "
                                 "está certificado. No se puede enviar el mensaje")
        elif send_message == -4:
            messagebox.showerror("Error",
                                 "Debes de estar certificado para enviar mensajes")
        else:
            messagebox.showinfo("Éxito", "Mensaje enviado con éxito")
            self.show_main_log_in()

    # Método para guardar la nueva contraseña
    def submit_new_password(self):
        new_password = self.entry_new_password.get()
        confirm_password = self.entry_confirm_password.get()

        if not new_password or not confirm_password:
            messagebox.showerror("Error",
                                 "Ambos campos de contraseña son obligatorios")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        if len(new_password) < 8:
            messagebox.showerror("Error",
                                 "La contraseña debe tener al menos 8 caracteres")
            return

        self.recover.update_password(self.username_recover_password,
                                     new_password)
        self.username_recover_password = None
        messagebox.showinfo("Éxito", "Contraseña actualizada con éxito")
        self.show_login()

    # Método para reservar una pista
    def submit_reservation(self):
        username = self.logged_in_username.get()
        time = self.time_var.get()
        court = self.court_var.get()
        credit_card = self.entry_bank_account.get()

        if not all([time, court, credit_card]):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        public_key_card = self.crypto.serialize_public_key(self.user.get_public_key(username))

        if self.reserve.reserve_court(username, time, court,
                                      credit_card,
                                      public_key_card) == -1:
            messagebox.showerror("Error", "Error al reservar la pista")
        else:
            messagebox.showinfo("Éxito",
                                f"Pista reservada con éxito para {username}")
            self.show_main_log_in()

    # Método para cargar los mensajes recibidos
    def load_messages_receiver(self):
        # Limpiar el frame de mensajes
        for widget in self.frame_view_messages_receive.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.destroy()

        messages = self.message.get_messages_receiver(self.logged_in_username.get())

        for message in messages:

            message_decode = self.crypto.decrypt_rsa(
                self.logged_in_username.get(), message[2],
                self.logged_in_password, message[4], message[6])

            sender_publik_key = self.user.get_public_key(message[0])
            sender_publik_key = serialization.load_pem_public_key(
                sender_publik_key.encode())

            # Verificar la firma digital, se altera el mensaje para
            # comprobarlo. Funcionamiento:
            # 1. Se altera el mensaje
            # 2. Cambiar parametros de signature_bool
            '''altered_message = message_decode + "altered"'''
            signature_bool = self.crypto.verify_signature(message_decode,message[8],
                                                          sender_publik_key)

            if not signature_bool:
                # Crear un frame para cada mensaje
                message_frame = tk.Frame(self.frame_view_messages_receive, bg="#e0f7fa",
                                         bd=2, relief="groove")
                message_frame.pack(pady=5, padx=10, fill="x")

                # Añadir el contenido del mensaje al frame
                tk.Label(message_frame, text=f"From: {message[0]}",
                         font=("Arial", 12), bg="#e0f7fa").pack(anchor="w", padx=5,
                                                                pady=2)
                tk.Label(message_frame, text=message_decode, font=("Arial", 12),
                         bg="#e0f7fa", wraplength=380, justify="left").pack(
                    anchor="w", padx=5, pady=2)

                # Añadir icono de tic y mensaje verificado
                verified_frame = tk.Frame(message_frame, bg="#e0f7fa")
                verified_frame.pack(anchor="e", padx=5, pady=2)
                tk.Label(verified_frame, text="✗", font=("Arial", 12),
                         bg="#e0f7fa", fg="red").pack(side=tk.LEFT)
                tk.Label(verified_frame, text="Mensaje no verificado con "
                                              "firma digital",
                         font=("Arial", 12), bg="#e0f7fa", fg="red").pack(
                    side=tk.LEFT)

            else:
                # Crear un frame para cada mensaje
                message_frame = tk.Frame(self.frame_view_messages_receive,
                                         bg="#e0f7fa",
                                         bd=2, relief="groove")
                message_frame.pack(pady=5, padx=10, fill="x")

                # Añadir el contenido del mensaje al frame
                tk.Label(message_frame, text=f"From: {message[0]}",
                         font=("Arial", 12), bg="#e0f7fa").pack(anchor="w",
                                                                padx=5, pady=2)
                tk.Label(message_frame, text=message_decode,
                         font=("Arial", 12),
                         bg="#e0f7fa", wraplength=380, justify="left").pack(
                    anchor="w", padx=5, pady=2)

                # Añadir icono de tic y mensaje verificado
                verified_frame = tk.Frame(message_frame, bg="#e0f7fa")
                verified_frame.pack(anchor="e", padx=5, pady=2)
                tk.Label(verified_frame, text="✔", font=("Arial", 12),
                         bg="#e0f7fa", fg="green").pack(side=tk.LEFT)
                tk.Label(verified_frame, text="Mensaje verificado con firma "
                                              "digital",
                         font=("Arial", 12), bg="#e0f7fa", fg="green").pack(
                    side=tk.LEFT)

    # Método para cargar los mensajes enviados
    def load_messages_sender(self):
        # Limpiar el frame de mensajes
        for widget in self.frame_view_messages_sent.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.destroy()

        messages = self.message.get_messages_sender(self.logged_in_username.get())
        for message in messages:
            message_decode = self.crypto.decrypt_rsa(
                self.logged_in_username.get(), message[3],
                self.logged_in_password, message[5], message[7])

            # Crear un frame para cada mensaje
            message_frame = tk.Frame(self.frame_view_messages_sent, bg="#e0f7fa",
                                     bd=2, relief="groove")
            message_frame.pack(pady=5, padx=10, fill="x")

            # Añadir el contenido del mensaje al frame
            tk.Label(message_frame, text=f"To: {message[1]}",
                     font=("Arial", 12), bg="#e0f7fa").pack(anchor="w", padx=5,
                                                            pady=2)
            tk.Label(message_frame, text=message_decode, font=("Arial", 12),
                     bg="#e0f7fa", wraplength=380, justify="left").pack(
                anchor="w", padx=5, pady=2)

    # Método para la interfaz
    def toggle_password_visibility(self, entry, button):
        if entry.cget('show') == '*':
            entry.config(show='')
            button.config(text='Esconder')
        else:
            entry.config(show='*')
            button.config(text='Mostar')


    def limit_message_length(self, *args):
        current_length = len(self.entry_message.get())
        remaining_chars = 100 - current_length
        if current_length > 100:
            self.entry_message.set(self.entry_message.get()[:100])
            remaining_chars = 0
        self.char_count_var.set(f"Faltan {remaining_chars} carcateres")

    def validate_message_length(self, new_text):
        if len(new_text) > 100:
            return False
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = PadelApp(root)
    root.mainloop()
