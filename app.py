from flask import Flask, request, jsonify, redirect, url_for, send_from_directory, session, make_response
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime
import secrets
from functools import wraps
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__, static_folder='static')
app.config['SESSION_COOKIE_DOMAIN'] = None
app.secret_key = 'clave-super-secreta-mercado-masivo'  # Cambia esto en producción
app.config['GOOGLE_CLIENT_ID'] = '1032458150548-djrlqo68jvitia9a9lmumb1o94qv32e7.apps.googleusercontent.com'  # Reemplaza con tu Client ID de Google

# ------------------- CONEXIÓN A BASE DE DATOS -------------------
db_config = {
    'host': '186.81.194.142',
    'user': 'root',
    'password': 'Database',
    'database': 'miscereG',
    'port': 3306,
    'autocommit': True,
    'charset': 'utf8mb4'
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# ------------------- DECORADOR PARA LOGIN REQUERIDO -------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Acceso no autorizado'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ------------------- RUTAS DE AUTENTICACIÓN -------------------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['Nombre', 'Apellido', 'NombreUsuario', 'Correo', 'Clave', 'ConfirmarClave', 'userType']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    if data['Clave'] != data['ConfirmarClave']:
        return jsonify({'error': 'Las contraseñas no coinciden'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verificar si el correo o nombre de usuario ya existen
        cursor.execute("SELECT * FROM Usuario WHERE Correo = %s OR NombreUsuario = %s", 
                      (data['Correo'], data['NombreUsuario']))
        existing_user = cursor.fetchone()
        
        if existing_user:
            return jsonify({'error': 'El correo o nombre de usuario ya están registrados'}), 400
        
        # Generar salt y hash de la contraseña
        salt = secrets.token_hex(16)
        hashed_password = generate_password_hash(data['Clave'] + salt)
        
        # Insertar nuevo usuario
        insert_query = """
        INSERT INTO Usuario (
            Nombre, Apellido, NombreUsuario, Correo, Telefono, Cargo, Clave, Salt,
            Estado, FechaRegistro, Genero, FechaNacimiento
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s)
        """
        
        user_data = (
            data['Nombre'],
            data['Apellido'],
            data['NombreUsuario'],
            data['Correo'],
            data.get('Telefono', None),
            data['userType'],
            hashed_password,
            salt,
            'pendiente',  # Estado inicial
            data.get('Genero', 'prefiero_no_decir'),
            data.get('FechaNacimiento', None)
        )
        
        cursor.execute(insert_query, user_data)
        user_id = cursor.lastrowid
        
        # Dependiendo del tipo de usuario, insertar en la tabla correspondiente
        if data['userType'] == 'proveedor':
            cursor.execute("INSERT INTO Proveedor (IdUsuario, Empresa, RFC, CategoriaProveedor) VALUES (%s, %s, %s, %s)",
                          (user_id, 'Empresa por definir', 'RFC por definir', 'Categoría por definir'))
        elif data['userType'] == 'owner':
            cursor.execute("INSERT INTO Owner (IdUsuario, NombreTienda, UbicacionTienda) VALUES (%s, %s, %s)",
                          (user_id, 'Tienda por definir', 'Ubicación por definir'))
        elif data['userType'] == 'cliente':
            cursor.execute("INSERT INTO Cliente (IdUsuario) VALUES (%s)", (user_id,))
        
        conn.commit()
        
        # Iniciar sesión automáticamente después del registro
        session['user_id'] = user_id
        session['user_type'] = data['userType']
        
        return jsonify({
            'message': 'Registro exitoso',
            'user_id': user_id,
            'user_type': data['userType']
        }), 201
        
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if 'Correo' not in data or 'Clave' not in data:
        return jsonify({'error': 'Correo y contraseña son requeridos'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT Id, Nombre, Apellido, NombreUsuario, Correo, Cargo, Clave, Salt, Estado 
            FROM Usuario 
            WHERE Correo = %s
        """, (data['Correo'],))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Credenciales incorrectas'}), 401
        
        if user['Estado'] != 'activo':
            return jsonify({'error': 'Tu cuenta no está activa'}), 403
        
        if not check_password_hash(user['Clave'], data['Clave'] + user['Salt']):
            return jsonify({'error': 'Credenciales incorrectas'}), 401
        
        # Actualizar último login
        cursor.execute("UPDATE Usuario SET UltimoLogin = NOW() WHERE Id = %s", (user['Id'],))
        conn.commit()
        
        # Establecer sesión
        session['user_id'] = user['Id']
        session['user_type'] = user['Cargo']
        
        return jsonify({
            'message': 'Inicio de sesión exitoso',
            'user': {
                'id': user['Id'],
                'nombre': user['Nombre'],
                'apellido': user['Apellido'],
                'email': user['Correo'],
                'username': user['NombreUsuario'],
                'type': user['Cargo']
            }
        })
        
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/google-auth', methods=['POST'])
def google_auth():
    data = request.get_json()
    
    if 'token' not in data:
        return jsonify({'error': 'Token de Google es requerido'}), 400
    
    try:
        # Verificar el token de Google
        idinfo = id_token.verify_oauth2_token(
            data['token'], 
            google_requests.Request(), 
            app.config['GOOGLE_CLIENT_ID']
        )
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Issuer incorrecto')
        
        # Extraer información del usuario
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')
        given_name = idinfo.get('given_name', '')
        family_name = idinfo.get('family_name', '')
        picture = idinfo.get('picture', '')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Verificar si el usuario ya existe
            cursor.execute("""
                SELECT Id, Nombre, Apellido, NombreUsuario, Cargo, Estado 
                FROM Usuario 
                WHERE GoogleId = %s OR Correo = %s
            """, (google_id, email))
            
            user = cursor.fetchone()
            
            if user:
                # Actualizar tokens de Google
                cursor.execute("""
                    UPDATE Usuario 
                    SET GoogleToken = %s, GoogleRefreshToken = %s, UltimoLogin = NOW() 
                    WHERE Id = %s
                """, (data['token'], data.get('refreshToken', ''), user['Id']))
                conn.commit()
                
                if user['Estado'] != 'activo':
                    return jsonify({'error': 'Tu cuenta no está activa'}), 403
                
                # Establecer sesión
                session['user_id'] = user['Id']
                session['user_type'] = user['Cargo']
                
                return jsonify({
                    'message': 'Inicio de sesión con Google exitoso',
                    'user': {
                        'id': user['Id'],
                        'nombre': user['Nombre'],
                        'apellido': user['Apellido'],
                        'email': email,
                        'username': user['NombreUsuario'],
                        'type': user['Cargo']
                    }
                })
            else:
                # Crear nuevo usuario
                username = email.split('@')[0]
                if len(username) > 30:
                    username = username[:30]
                
                # Verificar si el nombre de usuario ya existe
                cursor.execute("SELECT NombreUsuario FROM Usuario WHERE NombreUsuario = %s", (username,))
                if cursor.fetchone():
                    username = f"{username}_{secrets.token_hex(4)}"[:30]  # Añadir sufijo aleatorio
                
                insert_query = """
                INSERT INTO Usuario (
                    Nombre, Apellido, NombreUsuario, Correo, Foto, Cargo, 
                    GoogleId, GoogleToken, GoogleRefreshToken, Estado, FechaRegistro
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """
                
                user_data = (
                    given_name,
                    family_name,
                    username,
                    email,
                    picture,
                    'cliente',  # Por defecto como cliente
                    google_id,
                    data['token'],
                    data.get('refreshToken', ''),
                    'activo'
                )
                
                cursor.execute(insert_query, user_data)
                user_id = cursor.lastrowid
                
                # Insertar en tabla Cliente
                cursor.execute("INSERT INTO Cliente (IdUsuario) VALUES (%s)", (user_id,))
                conn.commit()
                
                # Establecer sesión
                session['user_id'] = user_id
                session['user_type'] = 'cliente'
                
                return jsonify({
                    'message': 'Registro con Google exitoso',
                    'user': {
                        'id': user_id,
                        'nombre': given_name,
                        'apellido': family_name,
                        'email': email,
                        'username': username,
                        'type': 'cliente'
                    }
                }), 201
                
        except Error as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except ValueError as e:
        return jsonify({'error': 'Token de Google inválido', 'details': str(e)}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Sesión cerrada exitosamente'})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT Id, Nombre, Apellido, NombreUsuario, Correo, Cargo 
                FROM Usuario 
                WHERE Id = %s
            """, (session['user_id'],))
            
            user = cursor.fetchone()
            
            if not user:
                session.clear()
                return jsonify({'isAuthenticated': False}), 200
            
            return jsonify({
                'isAuthenticated': True,
                'user': {
                    'id': user['Id'],
                    'nombre': user['Nombre'],
                    'apellido': user['Apellido'],
                    'email': user['Correo'],
                    'username': user['NombreUsuario'],
                    'type': user['Cargo']
                }
            })
            
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    
    return jsonify({'isAuthenticated': False}), 200

# ------------------- RUTA PRINCIPAL PARA SERVIR EL HTML -------------------
@app.route('/', methods=['GET'])    
def index():
    return app.send_static_file('acceso.html')

# ------------------- SERVIR ARCHIVOS ESTÁTICOS -------------------
@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# ------------------- PREVENCIÓN DE CACHÉ -------------------
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# ------------------- MAIN -------------------
if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')