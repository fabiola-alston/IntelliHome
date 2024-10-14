from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import re
import random
import smtplib
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = 'secretkey'

# Estado de la aplicación (True = habilitada, False = deshabilitada)
app_enabled = True  # La aplicación comienza habilitada

# Ruta al archivo donde se guardarán los usuarios
USERS_FILE = 'usuarios.txt'
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Definir un tiempo límite para el cambio de contraseña (2 minutos)
PASSWORD_CHANGE_INTERVAL = timedelta(minutes=2)

# Función para leer usuarios desde el archivo
def leer_usuarios():
    usuarios = []
    try:
        with open(USERS_FILE, 'r') as f:
            for line in f:
                # Desglosar todos los campos del archivo (alias, email, password, nombre, fecha_nacimiento, forma_pago, foto_perfil)
                datos = line.strip().split(',')
                
                # Solo obtenemos los 7 campos esperados (alias, email, password, nombre, fecha_nacimiento, forma_pago, foto_perfil)
                if len(datos) >= 7:
                    alias, email, password, nombre, fecha_nacimiento, forma_pago, foto_perfil = datos
                    usuarios.append({'alias': alias, 'email': email, 'password': password,'nombre': nombre, 'fecha_nacimiento': fecha_nacimiento, 'forma_pago': forma_pago, 'foto_perfil': foto_perfil})
                else:
                    print(f"Error en la línea: {line}. No tiene el formato correcto.")
    except FileNotFoundError:
        # Si el archivo no existe, devolvemos una lista vacía
        print("Archivo de usuarios no encontrado.")
    except Exception as e:
        # Cualquier otro error al leer el archivo
        print(f"Error al leer el archivo: {e}")
    return usuarios



# Función para verificar si el alias o correo ya existen
def alias_o_correo_duplicado(alias, email):
    usuarios = leer_usuarios()
    for usuario in usuarios:
        if usuario['alias'] == alias or usuario['email'] == email:
            return True
    return False

def registrar_usuario(alias, email, password, nombre, fecha_nacimiento, forma_pago, foto_perfil):
    try:
        with open(USERS_FILE, 'a') as f:
            # Escribimos los datos del usuario en el archivo
            f.write(f'{alias},{email},{password},{nombre},{fecha_nacimiento},{forma_pago},{foto_perfil}\n')
        print(f"Usuario {alias} registrado correctamente.")
    except Exception as e:
        print(f"Error al escribir en el archivo: {e}")
        flash("Ocurrió un error al registrar al usuario. Inténtalo de nuevo.")

# Función para validar la contraseña
def validación_contraseña(password):
    if len(password) < 7:
        return False, "La contraseña debe tener al menos 7 caracteres."
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "La contraseña debe contener al menos un símbolo especial."
    return True, "Contraseña válida."

# Función para enviar un correo electrónico con el código de verificación
def enviar_codigo(email, codigo):
    sender_email = "intellihome.playitaiguana@gmail.com"
    sender_password = "feum sttx vaqc peip"

    msg = EmailMessage()
    msg.set_content(f"""
    Estimado usuario,

    Saludos desde Intelli Home. A continuación, le proporcionamos su código de verificación:

    Código de verificación: {codigo}

    Por favor, ingrese este código en la página de verificación para completar su registro.

    ¡Gracias por confiar en nosotros!

    Atentamente,
    El equipo de Intelli Home.
    """)

    msg['Subject'] = 'Código de Verificación'
    msg['From'] = sender_email
    msg['To'] = email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

# Ruta para habilitar/deshabilitar la aplicación desde el panel de administración
@app.route('/toggle_app', methods=['POST'])
def toggle_app():
    global app_enabled
    action = request.form['action']
    if action == "Habilitar":
        app_enabled = True
        flash("La aplicación ha sido habilitada.")
    elif action == "Deshabilitar":
        app_enabled = False
        flash("La aplicación ha sido deshabilitada.")
    return redirect(url_for('admin_dashboard'))

app_enabled = True  # Inicialmente habilitado

@app.route('/toggle_website', methods=['GET', 'POST'])
def toggle_website():
    global app_enabled
    if 'user' in session and session['user'] == 'Admin':
        if request.method == 'POST':
            action = request.form['action']
            if action == 'Habilitar':
                app_enabled = True
                flash('El sitio web ha sido habilitado', 'success')
            elif action == 'Deshabilitar':
                app_enabled = False
                flash('El sitio web ha sido deshabilitado', 'warning')
        return render_template('toggle_website.html', app_enabled=app_enabled)
    else:
        return redirect(url_for('home'))



# Ruta para la página principal de inicio de sesión
@app.route('/')
def home():
    if not app_enabled:
        return "La aplicación está actualmente deshabilitada. Vuelve más tarde."
    return render_template('login.html')

# Ruta para el registro inicial
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        alias = request.form['alias']
        email = request.form['email']
        nombre = request.form['nombre']
        fecha_nacimiento = request.form['fecha_nacimiento']
        forma_pago = request.form['pago']
        
        # Validar si el alias o correo ya existen
        if alias_o_correo_duplicado(alias, email):
            flash("El alias o el correo ya están en uso. Por favor, elige otros.")
            return render_template('register.html')

        # Manejar la subida de la foto de perfil
        if 'foto_perfil' in request.files:
            foto = request.files['foto_perfil']
            if foto.filename != '':
                filename = secure_filename(foto.filename)
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = None
        else:
            filename = None

        # Guardar los datos en la sesión para la validación
        session['alias'] = alias
        session['email'] = email
        session['nombre'] = nombre
        session['fecha_nacimiento'] = fecha_nacimiento
        session['forma_pago'] = forma_pago
        session['foto_perfil'] = filename

        # Generar y enviar código de verificación con límite de 2 minutos
        session['codigo'] = random.randint(10000, 99999)
        session['codigo_expiracion'] = datetime.now(timezone.utc) + timedelta(minutes=2)
        session['intentos'] = 1  # Se permite un intento extra

        enviar_codigo(email, session['codigo'])
        
        return redirect(url_for('validar_correo'))
    return render_template('register.html')

# Ruta para validar el código enviado al correo
@app.route('/validar_correo', methods=['GET', 'POST'])
def validar_correo():
    if request.method == 'POST':
        codigo_ingresado = request.form['codigo']
        
        now = datetime.now(timezone.utc)
        codigo_expiracion = session['codigo_expiracion']
        
        # Verificar si el código ha expirado
        if now > codigo_expiracion:
            if session['intentos'] < 2:
                flash("El código ha expirado. Se enviará un nuevo código.")
                session['codigo'] = random.randint(10000, 99999)
                session['codigo_expiracion'] = datetime.now(timezone.utc) + timedelta(minutes=2)
                enviar_codigo(session['email'], session['codigo'])
                session['intentos'] += 1
            else:
                flash("El código ha expirado y ya no tienes más intentos.")
                return redirect(url_for('home'))
        elif str(codigo_ingresado) == str(session['codigo']):
            return redirect(url_for('validar_contraseña'))
        else:
            flash("Código incorrecto, intenta nuevamente.")
            return render_template('validar_correo.html')
    return render_template('validar_correo.html')

# Ruta para validar la contraseña
@app.route('/validar_contraseña', methods=['GET', 'POST'])
def validar_contraseña():
    if request.method == 'POST':
        password = request.form['password']
        valid, message = validación_contraseña(password)
        if valid:
            registrar_usuario(session['alias'], session['email'], password, session['nombre'],
                              session['fecha_nacimiento'], session['forma_pago'], session['foto_perfil'])
            flash("Usuario registrado correctamente")
            return redirect(url_for('home'))  # Redirigir al inicio de sesión
        else:
            flash(message)
            return render_template('validar_contraseña.html')
    return render_template('validar_contraseña.html')

# Ruta para manejar el inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    alias = request.form['alias']
    password = request.form['password']
    usuarios = leer_usuarios()

    for usuario in usuarios:
        if usuario['alias'] == alias and usuario['password'] == password:
            session['user'] = alias
            session['foto_perfil'] = usuario['foto_perfil']  # Guardar la foto en la sesión
            if alias == 'Admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
    flash("Usuario o contraseña incorrectos")
    return redirect(url_for('home'))

# Ruta para el panel de administración
@app.route('/admin')
def admin_dashboard():
    # Simular última vez que se cambió la contraseña si no está en la sesión
    if 'last_password_change' not in session:
        session['last_password_change'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    # Convertir el tiempo guardado en la sesión a datetime
    try:
        last_password_change = datetime.strptime(session['last_password_change'], '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        # Si la cadena no contiene microsegundos, intenta sin ellos
        last_password_change = datetime.strptime(session['last_password_change'], '%Y-%m-%d %H:%M:%S')

    # Verificar si han pasado más de 2 minutos desde el último cambio
    now = datetime.now()
    mostrar_mensaje = False
    if now - last_password_change > PASSWORD_CHANGE_INTERVAL:
        mostrar_mensaje = True

    return render_template('admin.html', user=session.get('user', 'Admin'), user_foto=session.get('user_foto'), mostrar_mensaje=mostrar_mensaje)

# Ruta para cambiar la contraseña
@app.route('/actualizar_contraseña', methods=['GET', 'POST'])
def actualizar_contrasena():
    if request.method == 'POST':
        nueva_contrasena = request.form['new_password']
        alias = session.get('user', 'Admin')

        # Actualizar la contraseña del usuario en el archivo
        actualizar_contraseña_usuario(alias, nueva_contrasena)

        # Actualizar la fecha de cambio de contraseña
        session['last_password_change'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        flash("Contraseña actualizada exitosamente.")
        return redirect(url_for('admin_dashboard'))
    return render_template('cambiar_contraseña.html')

# Función para actualizar la contraseña del usuario en el archivo
def actualizar_contraseña_usuario(alias, nueva_contraseña):
    usuarios = []
    try:
        with open('usuarios.txt', 'r') as f:
            for line in f:
                usuario_data = line.strip().split(',')
                if usuario_data[0] == alias:
                    # Actualizar la contraseña para el alias dado
                    usuario_data[2] = nueva_contraseña
                usuarios.append(usuario_data)
        
        # Escribir la actualización en el archivo
        with open('usuarios.txt', 'w') as f:
            for usuario in usuarios:
                f.write(','.join(usuario) + '\n')
    except FileNotFoundError:
        flash("Error: No se encontró el archivo de usuarios.")
        return




# Ruta para el panel de usuario normal
@app.route('/user')
def user_dashboard():
    if 'user' in session and session['user'] != 'Admin':
        user_foto = session.get('foto_perfil', None)  # Obtener la foto de perfil de la sesión
        return render_template('user.html', user=session['user'], user_foto=user_foto)
    else:
        return redirect(url_for('home'))

# Ruta para el perfil del usuario
@app.route('/perfil')
def perfil():
    if 'user' in session:
        # Recuperar los datos del usuario desde la sesión
        alias = session.get('user')
        foto_perfil = session.get('foto_perfil')
        email = session.get('email')  # Asegúrate de que el email esté en la sesión
        nombre = session.get('nombre')
        fecha_nacimiento = session.get('fecha_nacimiento')
        forma_pago = session.get('forma_pago')
        
        return render_template('perfil.html', alias=alias, foto_perfil=foto_perfil, email=email,
                               nombre=nombre, fecha_nacimiento=fecha_nacimiento, forma_pago=forma_pago)
    else:
        return redirect(url_for('home'))


# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


INFO_PAGOS_FILE = 'info_pago.txt'
# lee info de pagos del txt correspondiente
def leer_info_pagos(username):
    try:
        with open(INFO_PAGOS_FILE, 'r') as f:
            for line in f:
                datos = line.strip().split(',')
                if len(datos) == 8 and datos[0] == username:
                    return {
                        'card_number' : datos[1],
                        'card_holder' : datos[2],
                        'date' : datos[3],
                        'pin' : datos[4],
                        'brand' : datos[5],
                        'debt' : float(datos[6]),
                        'amount' : float(datos[7])
                    }
    except FileNotFoundError:
        print("Archivo no encontrado :(")
    return None


# guardar informacion de pago
def guardar_info_pago(username, card_number, card_holder, date, pin, brand, debt, amount):
    all_info = []
    found = False

    try: 
        with open(INFO_PAGOS_FILE, 'r') as f:
            for line in f:
                datos = line.strip().split(',')
                if datos[0] == username:
                    all_info.append(f"{username}, {card_number}, {card_holder}, {date}, {pin}, {brand}, {debt}, {amount}")
                    found = True
                else:
                    all_info.append(line.strip())
    except FileNotFoundError:
        pass

    if not found:
        all_info.append(f"{username}, {card_number}, {card_holder}, {date}, {pin}, {brand}, {debt}, {amount}")
    
    with open(INFO_PAGOS_FILE, 'w') as f:
        for info in all_info:
            f.write(info + '\n')

def guardar_info_pago_rapido(username, card_info):
    guardar_info_pago(username, card_info['card_number'], card_info['card_holder'], card_info['date'], card_info['pin'], card_info['brand'], card_info['debt'], card_info['amount'])

# pagina de pagos
@app.route('/pagos', methods=['GET', 'POST'])
def pagos():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    username = session['user']
    print(f"Username: {username}")

    card_info = leer_info_pagos(username) 
 
    if card_info:
        print("went in")
        
    else:
        guardar_info_pago(username, "- -", "- -", "- -", "- -", "- -")
        card_info = leer_info_pagos(username)
        print("didn't go in")
    
    return render_template('pagos.html', card_info=card_info)


@app.route('/add_pagos', methods=["GET", "POST"])
def add_pagos():
    return render_template('add_pagos.html')

@app.route('/guardar_pagos', methods=["POST"])
def guardar_pagos():
    card_number = request.form['card_number']
    card_holder = request.form['card_holder']
    month = request.form['month']
    year = request.form['year']
    pin = request.form['pin']

    print(card_number, card_holder, month, year, pin)
    
    # Aquí podrías guardar la información, procesarla o validarla
    # Por ejemplo, puedes crear un diccionario con la información:

    brand = ' '

    print(card_number[0])

    if card_number[0] == '1':
        brand = 'Visca'
    elif card_number[0] == '2':
        brand = 'MasterChef'
    elif card_number[0] == '3':
        brand = 'AmericanCity'
    elif card_number[0] == '5':
        brand = 'TicaPay'

    card_info = {
        'card_number': card_number,
        'card_holder': card_holder,
        'date': f"{month}/{year}",
        'pin': pin,
        'brand': brand
    }

    if 'user' not in session:
        return redirect(url_for('home'))
    
    username = session['user']

    guardar_info_pago(username, card_info['card_number'], card_info['card_holder'], card_info['date'], card_info['pin'], card_info['brand'], card_info['debt'], card_info['amount'])

    return render_template('guardar_pagos.html', card_info=card_info)

@app.route('/realizar_pagos', methods=["POST"])
def realizar_pagos():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    username = session['user']

    card_info = leer_info_pagos(username)

    return render_template('realizar_pagos.html', card_info = card_info)

@app.route('/realizando_pago', methods=['POST'])
def realizando_pagos():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    username = session['user']

    card_info = leer_info_pagos(username)

    if card_info['amount'] < card_info['debt']:
        message = "Error, fondos insuficientes."
        return render_template('pago_realizado_ventana.html', message=message)
    
    else:
        amount = card_info['amount'] - card_info['debt']
        card_info['amount'] = amount
        card_info['debt'] = 0
        guardar_info_pago_rapido(username, card_info)
        message = "Pago realizado exitosamente. Puedes volver a la pagina principal."
        return render_template('pago_realizado_ventana.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
