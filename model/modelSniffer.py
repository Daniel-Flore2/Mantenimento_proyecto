from config.config import conexion

def crear_tabla():
    cursor = conexion.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sniff (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mac_src VARCHAR(20),
        ip_src VARCHAR(20),
        tam_src INT,
        fecha DATE,
        hora TIME
)
''')
