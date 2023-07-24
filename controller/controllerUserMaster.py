from flask import Blueprint, request, jsonify
from model.modelUserMaster import crear_tabla
from config.config import conexion
from flask_cors import CORS
from bcrypt import hashpw, checkpw, gensalt
import jwt
from functools import wraps

app3_bp = Blueprint('app3', __name__)

cursor = conexion.cursor()
crear_tabla()
CORS(app3_bp)

get_all = ("SELECT * FROM usuariosMaster")
secret_key = 'your-secret-key'
# Replace with your own secret key

# Decorador para verificar el token de autenticación
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]

        if not token:
            return jsonify({'mensaje': 'Token de autenticación faltante'}), 401

        try:
            data = jwt.decode(token, secret_key)
        except:
            return jsonify({'mensaje': 'Token de autenticación inválido'}), 401

        return f(*args, **kwargs)

    return decorated

@app3_bp.route('/userMaster', methods=['POST'])
def crear_usuario():
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    correo = datos_json['correo']
    contraseña = datos_json['contraseña']
    nombre_completo = datos_json['nombre_completo']
    telefono = datos_json['telefono']

    # Verificar si el correo ya está registrado en la tabla usuariosMaster
    cursor.execute('SELECT * FROM usuarios WHERE correo=%s', (correo,))
    registro_master = cursor.fetchone()
    if registro_master:
        # El correo ya está registrado en la tabla usuariosMaster, responder con un mensaje de error
        response_data = {'mensaje': 'El correo ya está registrado como usuario'}
        return jsonify(response_data), 409

    # Verificar si el correo ya está registrado en la tabla usuarios
    cursor.execute('SELECT * FROM usuariosMaster WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if registro:
        # El correo ya está registrado en la tabla usuarios, responder con un mensaje de error
        response_data = {'mensaje': 'El correo ya está registrado como usuariosMaster'}
        return jsonify(response_data), 409

    # Hash de la contraseña
    hashed_password = hashpw(contraseña.encode('utf-8'), gensalt())

    # Insertar los datos en la tabla
    cursor.execute('INSERT INTO usuariosMaster (correo, contraseña, nombre_completo, telefono) VALUES (%s, %s, %s, %s)', (correo, hashed_password, nombre_completo, telefono))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'UsuarioMaster creado correctamente'}
    return jsonify(response_data)

@app3_bp.route('/userMaster', methods=['GET'])
def get_usuarios():
    # get all data from the usuarios table
    cursor.execute(get_all)
    data = cursor.fetchall()

    # convert data to JSON format
    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'correo': row[1],
            'contraseña': row[2],
            'nombre_completo': row[3],
            'telefono': row[4]
        })
    return jsonify(json_data)

@app3_bp.route('/loginMaster', methods=['POST'])
def login():
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    correo = datos_json['correo']
    contraseña = datos_json['contraseña']

    # Buscar al usuario en la tabla
    cursor.execute('SELECT * FROM usuariosMaster WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if not registro:
        # El correo no está registrado, responder con un mensaje de error
        return jsonify({'mensaje': 'Correo o contraseña incorrectos'}), 401

    # Verificar la contraseña
    if not checkpw(contraseña.encode('utf-8'), registro[2].encode('utf-8')):
        # La contraseña es incorrecta, responder con un mensaje de error
        return jsonify({'mensaje': 'Correo o contraseña incorrectos'}), 401

    # Generar el token de autenticación
    token = jwt.encode({'correo': correo}, secret_key)

    # Responder con el token
    return jsonify({'token': token})

@app3_bp.route('/userMaster/<string:correo>', methods=['PUT'])
@token_required
def actualizar_contraseña_master(correo):
    # Obtener los datos JSON enviados
    datos_json = request.get_json()
    nueva_contraseña = datos_json['nueva_contraseña']

    # Buscar al usuario Master en la tabla
    cursor.execute('SELECT * FROM usuariosMaster WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if not registro:
        # El usuario Master no está registrado, responder con un mensaje de error
        response_data = {'mensaje': 'El usuario Master no existe'}
        return jsonify(response_data), 404

    # Hash de la nueva contraseña
    hashed_password = hashpw(nueva_contraseña.encode('utf-8'), gensalt())

    # Actualizar la contraseña del usuario Master
    cursor.execute('UPDATE usuariosMaster SET contraseña=%s WHERE correo=%s', (hashed_password, correo))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'Contraseña actualizada correctamente'}
    return jsonify(response_data)
