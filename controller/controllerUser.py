from flask import Blueprint, request, jsonify
from model.modelUser import crear_tabla
from config.config import conexion
from flask_cors import CORS


app1_bp = Blueprint('app1', __name__)

cursor = conexion.cursor()
crear_tabla()
CORS(app1_bp)

get_all = ("SELECT * FROM usuarios")
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
      #  return 'El correo ya está registrado en la tabla usuariosMaster', 409
        response_data = {'mensaje': 'El correo ya está registrado como usuariosMaster'}
        return jsonify(response_data), 409
    
    # Verificar si el correo ya está registrado en la tabla usuarios
    cursor.execute('SELECT * FROM usuarios WHERE correo=%s', (correo,))
    registro = cursor.fetchone()
    if registro:
        # El correo ya está registrado en la tabla usuarios, responder con un mensaje de error
        #return 'El correo ya está registrado en la tabla usuarios', 409
        response_data = {'mensaje': 'El correo ya está registrado '}
        return jsonify(response_data), 409
    
    # Insertar los datos en la tabla
    cursor.execute('INSERT INTO usuarios (correo, contraseña, nombre_completo, telefono) VALUES (%s, %s, %s, %s)', (correo, contraseña, nombre_completo, telefono))
    conexion.commit()
    
    # Responder con un mensaje de éxito
   # return 'Usuario creado correctamente'
    response_data = {'mensaje': 'Usuario creado correctamente'}
    return jsonify(response_data)

@app1_bp.route('/usuarios', methods=['GET'])
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
    if registro[2] != contraseña:
        # La contraseña es incorrecta, responder con un mensaje de error
        return 'Correo o contraseña incorrectos', 401
    
    # Crear un objeto con los datos del usuario
    usuario = {
        'id': registro[0],
        'correo': registro[1],
        'nombre_completo': registro[3],
        'telefono': registro[4]
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
    
    # Actualizar la contraseña del usuario
    cursor.execute('UPDATE usuarios SET contraseña=%s WHERE correo=%s', (nueva_contraseña, correo))
    conexion.commit()

    # Responder con un mensaje de éxito
    response_data = {'mensaje': 'Contraseña actualizada correctamente'}
    return jsonify(response_data)
