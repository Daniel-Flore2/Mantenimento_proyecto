from config.config import conexion

def crear_tabla():
    cursor = conexion.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        correo VARCHAR(50),
        contraseña VARCHAR(50),
        nombre_completo VARCHAR(100),
        telefono VARCHAR(20)
    )
    """)
