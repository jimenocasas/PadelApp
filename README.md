# PadelApp – Plataforma Segura para Gestión de Reservas Deportivas  
**Periodo:** Septiembre 2024 – Diciembre 2024  

## Tecnologías y enfoques
- Desarrollo seguro de aplicaciones con Python  
- Diseño modular de software  
- Ciberseguridad aplicada y criptografía  

## Descripción del proyecto
Aplicación desarrollada en equipo para la gestión de reservas de pistas de pádel, con un enfoque en **seguridad y criptografía aplicada**.  

### Funcionalidades principales
- Autenticación robusta mediante hashing seguro de contraseñas (PBKDF2-HMAC-SHA256).  
- Mensajería segura entre usuarios con cifrado RSA y verificación mediante firmas digitales (RSASSA-PSS + SHA-256).  
- Infraestructura de clave pública (PKI) con jerarquía extendida: autoridad raíz y subordinadas, emisión/verificación de certificados y control de identidad de usuarios.  
- Protección de datos sensibles mediante almacenamiento cifrado en base de datos y recuperación de claves con contraseña maestra.  
- Interfaz gráfica (Tkinter) para la gestión de usuarios, reservas, mensajería y certificados.  
