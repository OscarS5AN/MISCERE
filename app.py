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

# ------------------- FUNCIÓN PARA OBTENER URL DE REDIRECCIÓN -------------------
def get_redirect_url(user_type):
    if user_type == 'cliente':
        return '/panel.html'
    elif user_type == 'proveedor':
        return '/panel-proveedor.html'
    elif user_type == 'owner':
        return '/panel-owner.html'
    elif user_type == 'administrador':
        return '/panel-admin.html'
    else:
        return '/panel.html'

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
            'user_type': data['userType'],
            'redirect': get_redirect_url(data['userType'])
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
            },
            'redirect': get_redirect_url(user['Cargo'])
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
                    },
                    'redirect': get_redirect_url(user['Cargo'])
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
                    },
                    'redirect': '/panel.html'
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
                SELECT Id, Nombre, Apellido, NombreUsuario, Correo, Telefono, Cargo, Foto, 
                       Genero, FechaNacimiento, Estado 
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
                    'Nombre': user['Nombre'],
                    'Apellido': user['Apellido'],
                    'NombreUsuario': user['NombreUsuario'],
                    'email': user['Correo'],
                    'Telefono': user['Telefono'],
                    'type': user['Cargo'],
                    'Foto': user['Foto'],
                    'Genero': user['Genero'],
                    'FechaNacimiento': str(user['FechaNacimiento']) if user['FechaNacimiento'] else None,
                    'Estado': user['Estado']
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

# ------------------- RUTAS DE RECUPERACIÓN DE CONTRASEÑA -------------------
@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    
    if 'email' not in data:
        return jsonify({'error': 'Email es requerido'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT Id FROM Usuario WHERE Correo = %s", (data['email'],))
        user = cursor.fetchone()
        
        return jsonify({'exists': bool(user)})
        
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/check-phone', methods=['POST'])
def check_phone():
    data = request.get_json()
    
    if 'phone' not in data:
        return jsonify({'error': 'Teléfono es requerido'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT Id FROM Usuario WHERE Telefono = %s", (data['phone'],))
        user = cursor.fetchone()
        
        return jsonify({'exists': bool(user)})
        
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/send-recovery-code', methods=['POST'])
def send_recovery_code():
    data = request.get_json()
    
    if 'method' not in data:
        return jsonify({'error': 'Método de recuperación es requerido'}), 400
    
    # Generar código de 6 dígitos
    code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    if data['method'] == 'email':
        if 'email' not in data:
            return jsonify({'error': 'Email es requerido para este método'}), 400
        
        print(f"Código de recuperación para {data['email']}: {code}")
        return jsonify({'message': 'Código enviado al correo electrónico', 'code': code})
    
    elif data['method'] == 'phone':
        if 'phone' not in data:
            return jsonify({'error': 'Teléfono es requerido para este método'}), 400
        
        print(f"Código de recuperación para {data['phone']}: {code}")
        return jsonify({'message': 'Código enviado al teléfono', 'code': code})
    
    return jsonify({'error': 'Método de recuperación no válido'}), 400

@app.route('/api/verify-recovery-code', methods=['POST'])
def verify_recovery_code():
    data = request.get_json()
    
    if 'code' not in data or 'method' not in data:
        return jsonify({'error': 'Código y método son requeridos'}), 400
    
    if len(data['code']) != 6 or not data['code'].isdigit():
        return jsonify({'error': 'Código inválido'}), 400
    
    return jsonify({'message': 'Código verificado correctamente'})

@app.route('/api/update-password', methods=['POST'])
def update_password():
    data = request.get_json()
    
    if 'newPassword' not in data or 'method' not in data:
        return jsonify({'error': 'Nueva contraseña y método son requeridos'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Buscar usuario por email o teléfono
        if data['method'] == 'email':
            if 'email' not in data:
                return jsonify({'error': 'Email es requerido para este método'}), 400
            
            cursor.execute("SELECT Id, Salt FROM Usuario WHERE Correo = %s", (data['email'],))
        elif data['method'] == 'phone':
            if 'phone' not in data:
                return jsonify({'error': 'Teléfono es requerido para este método'}), 400
            
            cursor.execute("SELECT Id, Salt FROM Usuario WHERE Telefono = %s", (data['phone'],))
        else:
            return jsonify({'error': 'Método no válido'}), 400
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Generar nuevo hash de contraseña
        salt = secrets.token_hex(16) if not user['Salt'] else user['Salt']
        hashed_password = generate_password_hash(data['newPassword'] + salt)
        
        # Actualizar contraseña
        cursor.execute("""
            UPDATE Usuario 
            SET Clave = %s, Salt = %s 
            WHERE Id = %s
        """, (hashed_password, salt, user['Id']))
        
        conn.commit()
        
        return jsonify({'message': 'Contraseña actualizada correctamente'})
        
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Ruta para servir changepassword.html
@app.route('/changepassword.html')
def change_password():
    return app.send_static_file('changepassword.html')

# ------------------- RUTAS DE PERFIL DE USUARIO -------------------
@app.route('/api/update-profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    
    if 'NombreUsuario' not in data:
        return jsonify({'error': 'Nombre de usuario es requerido'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verificar si el nuevo nombre de usuario ya existe (excepto para el usuario actual)
        cursor.execute("SELECT Id FROM Usuario WHERE NombreUsuario = %s AND Id != %s", 
                      (data['NombreUsuario'], session['user_id']))
        if cursor.fetchone():
            return jsonify({'error': 'El nombre de usuario ya está en uso'}), 400
        
        # Actualizar datos básicos
        update_query = """
        UPDATE Usuario 
        SET NombreUsuario = %s, Telefono = %s 
        WHERE Id = %s
        """
        cursor.execute(update_query, (data['NombreUsuario'], data.get('Telefono'), session['user_id']))
        
        # Cambiar contraseña si se proporcionó
        if 'currentPassword' in data and 'newPassword' in data:
            # Verificar contraseña actual
            cursor.execute("SELECT Clave, Salt FROM Usuario WHERE Id = %s", (session['user_id'],))
            user = cursor.fetchone()
            
            if not check_password_hash(user['Clave'], data['currentPassword'] + user['Salt']):
                return jsonify({'error': 'La contraseña actual es incorrecta'}), 401
            
            # Generar nuevo hash de contraseña
            salt = secrets.token_hex(16)
            hashed_password = generate_password_hash(data['newPassword'] + salt)
            
            # Actualizar contraseña
            cursor.execute("UPDATE Usuario SET Clave = %s, Salt = %s WHERE Id = %s", 
                          (hashed_password, salt, session['user_id']))
        
        conn.commit()
        
        # Obtener datos actualizados del usuario
        cursor.execute("""
            SELECT Id, Nombre, Apellido, NombreUsuario, Correo, Telefono, Cargo, Foto, Genero, FechaNacimiento 
            FROM Usuario 
            WHERE Id = %s
        """, (session['user_id'],))
        
        updated_user = cursor.fetchone()
        
        return jsonify({
            'message': 'Perfil actualizado correctamente',
            'user': {
                'id': updated_user['Id'],
                'Nombre': updated_user['Nombre'],
                'Apellido': updated_user['Apellido'],
                'NombreUsuario': updated_user['NombreUsuario'],
                'email': updated_user['Correo'],
                'Telefono': updated_user['Telefono'],
                'type': updated_user['Cargo'],
                'Foto': updated_user['Foto'],
                'Genero': updated_user['Genero'],
                'FechaNacimiento': str(updated_user['FechaNacimiento']) if updated_user['FechaNacimiento'] else None
            }
        })
        
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/update-avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'No se proporcionó archivo de avatar'}), 400
    
    avatar_file = request.files['avatar']
    
    if avatar_file.filename == '':
        return jsonify({'error': 'No se seleccionó archivo'}), 400
    
    # Validar tipo y tamaño de archivo
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in avatar_file.filename or avatar_file.filename.split('.')[-1].lower() not in allowed_extensions:
        return jsonify({'error': 'Formato de archivo no permitido'}), 400
    
    if avatar_file.content_length > 2 * 1024 * 1024:  # 2MB
        return jsonify({'error': 'El archivo no debe exceder los 2MB'}), 400
    
    try:
        # En un entorno real, aquí subirías el archivo a un servicio como AWS S3 o similar
        # Por simplicidad, en este ejemplo simularemos la subida
        
        # Generar nombre único para el archivo
        filename = f"avatar_{session['user_id']}_{secrets.token_hex(8)}.{avatar_file.filename.split('.')[-1].lower()}"
        
        # Ruta donde se guardaría el archivo (en producción usarías un servicio de almacenamiento)
        avatar_path = os.path.join('static', 'avatars', filename)
        avatar_file.save(avatar_path)
        
        # URL del avatar (en producción sería la URL del servicio de almacenamiento)
        avatar_url = f"/static/avatars/{filename}"
        
        # Actualizar la base de datos
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE Usuario SET Foto = %s WHERE Id = %s", (avatar_url, session['user_id']))
            conn.commit()
            
            return jsonify({
                'message': 'Avatar actualizado correctamente',
                'avatarUrl': avatar_url
            })
        except Error as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remove-avatar', methods=['DELETE'])
@login_required
def remove_avatar():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Error de conexión a la base de datos'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Obtener la foto actual para eliminarla del almacenamiento (en producción)
        cursor.execute("SELECT Foto FROM Usuario WHERE Id = %s", (session['user_id'],))
        current_avatar = cursor.fetchone()[0]
        
        # En producción, aquí eliminarías el archivo del servicio de almacenamiento
        if current_avatar:
             try:
                 os.remove(os.path.join('static', 'avatars', current_avatar.split('/')[-1]))
             except:
                 pass
        
        # Actualizar la base de datos
        cursor.execute("UPDATE Usuario SET Foto = NULL WHERE Id = %s", (session['user_id'],))
        conn.commit()
        
        return jsonify({'message': 'Avatar eliminado correctamente'})
        
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# ------------------- MAIN -------------------
if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')