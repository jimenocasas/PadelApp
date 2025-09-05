# PadelApp
Aplicación para gestionar reservas de pistas de pádel con un enfoque en  seguridad y criptografía aplicada.
El sistema integra:
Autenticación robusta mediante hashing seguro de contraseñas (PBKDF2-HMAC-SHA256).
Mensajería segura entre usuarios, con cifrado RSA y veri cación mediante rmas digitales (RSASSA-PSS + SHA-256).
Implementación de una infraestructura de clave pública (PKI) con jerarquía extendida (autoridad raíz y subordinadas),
emisión/veri cación de certi cados y control de identidad de usuarios.
Protección de datos sensibles mediante almacenamiento cifrado en base de datos y recuperación de claves con contraseña
maestra.
Desarrollo de una interfaz grá ca funcional (Tkinter) que permite gestionar usuarios, reservas, mensajería y certi cados.
