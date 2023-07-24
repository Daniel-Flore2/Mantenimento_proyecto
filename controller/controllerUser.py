import jwt
import bcrypt
from flask import Blueprint, request, jsonify
from model.modelUser import crear_tabla
from config.config import conexion
from flask_cors import CORS


app1_bp = Blueprint('app1', __name__)

cursor = conexion.cursor()
crear_tabla()
CORS(app1_bp)

get_all = ("SELECT * FROM usuarios")

def encrypt_password(password):
    # Generar una sal aleatoria para el cifrado de la contraseña
    salt = bcrypt.gensalt()
    # Cifrar la contraseña utilizando bcrypt
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def verify_password(password, hashed_password):
    # Verificar si la contraseña coincide con el cifrado almacenado
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def generate_token(user_id):
    # Generar un token JWT con el ID de usuario como carga útil (payload)
    token = jwt.encode({'user_id': user_id}, 'secret_key', algorithm='HS256')
    return token.decode()

def verify_token(token):
    try:
        # Verificar y decodificar el token JWT
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        # El token ha expirado
        return None
    except jwt.InvalidTokenError:
        # El token no es válido
        return None

@app1_bp.route('/usuarios', methods=['POST'])
def crear_usuario():
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    correo = datos_json['correo']
    contraseña = datos_json['contraseña']
    nombre_completo = datos_json['nombre_completo']
    telefono = datos_json['telefono']

    # Verificar si el correo ya está registrado en la tabla usuariosMaster
    cursor.execute('SELECT * FROM usuariosMaster WHERE correo=%s', (correo,))
    registro_master = cursor.fetchone()
    if registro_master:
        # El correo ya está registrado en la tabla usuariosMaster, responder con un mensaje de error
        response_data = {'mensaje': 'El correo ya está registrado como usuariosMaster'}
        return jsonify(response_data), 409

    # Verificar si el correo ya está registrado en la tabla usuarios
    cursor.execute('SELECT * FROM usuarios WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if registro:
        # El correo ya está registrado en la tabla usuarios, responder con un mensaje de error
        response_data = {'mensaje': 'El correo ya está registrado '}
        return jsonify(response_data), 409

    # Encriptar la contraseña
    contraseña_encriptada = encrypt_password(contraseña)

    # Insertar los datos en la tabla
    cursor.execute('INSERT INTO usuarios (correo, contraseña, nombre_completo, telefono) VALUES (%s, %s, %s, %s)', (correo, contraseña_encriptada, nombre_completo, telefono))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'Usuario creado correctamente'}
    return jsonify(response_data)


@app1_bp.route('/usuarios', methods=['GET'])
def get_usuarios():
    # Obtener todos los datos de la tabla usuarios
    cursor.execute(get_all)
    data = cursor.fetchall()

    # Convertir los datos a formato JSON
    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'correo': row[1],
            'nombre_completo': row[3],
            'telefono': row[4]
        })
    return jsonify(json_data)


@app1_bp.route('/login', methods=['POST'])
def login():
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    correo = datos_json['correo']
    contraseña = datos_json['contraseña']

    # Buscar al usuario en la tabla
    cursor.execute('SELECT * FROM usuarios WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if not registro:
        # El correo no está registrado, responder con un mensaje de error
        return 'Correo o contraseña incorrectos', 401

    # Verificar la contraseña
    if not verify_password(contraseña, registro[2]):
        # La contraseña es incorrecta, responder con un mensaje de error
        return 'Correo o contraseña incorrectos', 401

    # Generar un token JWT para el usuario
    token = generate_token(registro[0])

    # Crear un objeto con los datos del usuario
    usuario = {
        'id': registro[0],
        'correo': registro[1],
        'nombre_completo': registro[3],
        'telefono': registro[4],
        'token': token
    }

    # Responder con el objeto del usuario
    return jsonify(usuario)


@app1_bp.route('/usuarios/<int:id>', methods=['DELETE'])
def eliminar_usuario(id):
    # Buscar al usuario en la tabla
    cursor.execute('SELECT * FROM usuarios WHERE id=%s', (id,))
    registro = cursor.fetchone()
    if not registro:
        # El usuario no está registrado, responder con un mensaje de error
        response_data = {'mensaje': 'El usuario no existe'}
        return jsonify(response_data), 404

    # Eliminar al usuario de la tabla
    cursor.execute('DELETE FROM usuarios WHERE id=%s', (id,))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'Usuario eliminado correctamente'}
    return jsonify(response_data)


@app1_bp.route('/usuarios/<string:correo>', methods=['PUT'])
def actualizar_contraseña(correo):
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    nueva_contraseña = datos_json['nueva_contraseña']

    # Buscar al usuario en la tabla
    cursor.execute('SELECT * FROM usuarios WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if not registro:
        # El usuario no está registrado, responder con un mensaje de error
        response_data = {'mensaje': 'El usuario no existe'}
        return jsonify(response_data), 404

    # Encriptar la nueva contraseña
    nueva_contraseña_encriptada = encrypt_password(nueva_contraseña)

    # Actualizar la contraseña del usuario
    cursor.execute('UPDATE usuarios SET contraseña=%s WHERE correo=%s', (nueva_contraseña_encriptada, correo))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'Contraseña actualizada correctamente'}
    return jsonify(response_data)

