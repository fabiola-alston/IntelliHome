from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import re
import random
import smtplib
import json
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = "secretkey"

# Estado de la aplicación (True = habilitada, False = deshabilitada)
app_enabled = True  # La aplicación comienza habilitada

# Ruta al archivo donde se guardarán los usuarios
# USERS_FILE = "usuarios.txt"
USERS_FILE = "usuarios.json"
UPLOAD_FOLDER = "static/uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['JSON_AS_ASCII'] = False
# Definir un tiempo límite para el cambio de contraseña (2 minutos)
PASSWORD_CHANGE_INTERVAL = timedelta(minutes=2)


# Función para leer usuarios desde el archivo JSON
def leer_usuarios():
    usuarios = []
    administradores = []
    try:
        with open(USERS_FILE, "r", encoding='utf-8') as f:
            data = json.load(f)
            usuarios = data.get("usuarios", [])
            administradores = data.get("administradores", [])

        # Función para verificar campos requeridos
        def verificar_campos(usuario):
            required_fields = [
                "alias",
                "email",
                "password",
                "nombre",
                "fecha_nacimiento",
                "forma_pago",
                "foto_perfil",
                "casas",
            ]
            return all(field in usuario.keys() for field in required_fields)

        # Verificar campos para usuarios y administradores
        usuarios = [u for u in usuarios if verificar_campos(u)]
        administradores = [a for a in administradores if verificar_campos(a)]

        # Combinar usuarios y administradores en una sola lista
        todos_usuarios = usuarios + administradores

    except FileNotFoundError:
        print("Archivo de usuarios no encontrado.")
    except json.JSONDecodeError:
        print("Error al decodificar el archivo JSON.")
    except Exception as e:
        print(f"Error al leer el archivo: {e}")

    return todos_usuarios


# Asegúrate de que esta variable esté definida correctamente


# Función para verificar si el alias o correo ya existen
def alias_o_correo_duplicado(alias, email):
    usuarios = leer_usuarios()
    for usuario in usuarios:
        if usuario["alias"] == alias or usuario["email"] == email:
            return True
    return False


def registrar_usuario(
    alias,
    email,
    password,
    nombre,
    fecha_nacimiento,
    forma_pago,
    foto_perfil,
    casas=[],
    admin=False,
):
    nuevo_usuario = {
        "alias": alias,
        "email": email,
        "password": password,
        "nombre": nombre,
        "fecha_nacimiento": fecha_nacimiento,
        "forma_pago": forma_pago,
        "foto_perfil": foto_perfil,
        "casas": casas,
    }

    try:
        # Leer el archivo JSON existente
        with open(USERS_FILE, "r+", encoding='utf-8') as f:
            data = json.load(f)

            # Decidir si agregar a la lista de administradores o usuarios
            if admin:
                data["administradores"].append(nuevo_usuario)
            else:
                data["usuarios"].append(nuevo_usuario)

            # Volver al inicio del archivo y escribir los datos actualizados
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

        print(
            f"Usuario {alias} registrado correctamente como {'administrador' if admin else 'usuario'}."
        )
    except FileNotFoundError:
        # Si el archivo no existe, crearlo con la estructura correcta
        data = {"administradores": [], "usuarios": []}
        if admin:
            data["administradores"].append(nuevo_usuario)
        else:
            data["usuarios"].append(nuevo_usuario)
        with open(USERS_FILE, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(
            f"Archivo creado y usuario {alias} registrado correctamente como {'administrador' if admin else 'usuario'}."
        )
    except json.JSONDecodeError:
        print("Error al decodificar el archivo JSON existente.")
        flash(
            "Ocurrió un error al registrar al usuario. El archivo de usuarios está corrupto."
        )
    except Exception as e:
        print(f"Error al escribir en el archivo: {e}")
        flash("Ocurrió un error al registrar al usuario. Inténtalo de nuevo.")


# Función para validar la contraseña
def validación_contraseña(password):
    if len(password) < 7:
        return False, "La contraseña debe tener al menos 7 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r"\d", password):
        return False, "La contraseña debe contener al menos un número."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "La contraseña debe contener al menos un símbolo especial."
    return True, "Contraseña válida."


# Función para enviar un correo electrónico con el código de verificación
def enviar_codigo(email, codigo):
    sender_email = "intellihome.playitaiguana@gmail.com"
    sender_password = "feum sttx vaqc peip"

    msg = EmailMessage()
    msg.set_content(
        f"""
    Estimado usuario,

    Saludos desde Intelli Home. A continuación, le proporcionamos su código de verificación:

    Código de verificación: {codigo}

    Por favor, ingrese este código en la página de verificación para completar su registro.

    ¡Gracias por confiar en nosotros!

    Atentamente,
    El equipo de Intelli Home.
    """
    )

    msg["Subject"] = "Código de Verificación"
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Error al enviar el correo: {e}")


# Ruta para habilitar/deshabilitar la aplicación desde el panel de administración
@app.route("/toggle_app", methods=["POST"])
def toggle_app():
    global app_enabled
    action = request.form["action"]
    if action == "Habilitar":
        app_enabled = True
        flash("La aplicación ha sido habilitada.")
    elif action == "Deshabilitar":
        app_enabled = False
        flash("La aplicación ha sido deshabilitada.")
    return redirect(url_for("admin_dashboard"))


app_enabled = True  # Inicialmente habilitado


@app.route("/toggle_website", methods=["GET", "POST"])
def toggle_website():
    global app_enabled
    if "user" in session and session["user"] == "Admin":
        if request.method == "POST":
            action = request.form["action"]
            if action == "Habilitar":
                app_enabled = True
                flash("El sitio web ha sido habilitado", "success")
            elif action == "Deshabilitar":
                app_enabled = False
                flash("El sitio web ha sido deshabilitado", "warning")
        return render_template("toggle_website.html", app_enabled=app_enabled)
    else:
        return redirect(url_for("home"))


# Ruta para la página principal de inicio de sesión
@app.route("/")
def home():
    if not app_enabled:
        return "La aplicación está actualmente deshabilitada. Vuelve más tarde."
    return render_template("login.html")


# Ruta para el registro inicial
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        alias = request.form["alias"]
        email = request.form["email"]
        nombre = request.form["nombre"]
        fecha_nacimiento = request.form["fecha_nacimiento"]
        forma_pago = request.form["pago"]

        # Validar si el alias o correo ya existen
        if alias_o_correo_duplicado(alias, email):
            flash("El alias o el correo ya están en uso. Por favor, elige otros.")
            return render_template("register.html")

        # Manejar la subida de la foto de perfil
        if "foto_perfil" in request.files:
            foto = request.files["foto_perfil"]
            if foto.filename != "":
                filename = "profile/" + secure_filename(
                    f"{alias}.{datetime.now().strftime('%Y%m%d%H%M%S')}.{foto.filename}"
                )
                foto.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            else:
                filename = None
        else:
            filename = None

        # Guardar los datos en la sesión para la validación
        session["alias"] = alias
        session["email"] = email
        session["nombre"] = nombre
        session["fecha_nacimiento"] = fecha_nacimiento
        session["forma_pago"] = forma_pago
        session["foto_perfil"] = filename

        # Generar y enviar código de verificación con límite de 2 minutos
        session["codigo"] = random.randint(10000, 99999)
        session["codigo_expiracion"] = datetime.now(timezone.utc) + timedelta(minutes=2)
        session["intentos"] = 1  # Se permite un intento extra

        enviar_codigo(email, session["codigo"])

        return redirect(url_for("validar_correo"))
    return render_template("register.html")


# Ruta para validar el código enviado al correo
@app.route("/validar_correo", methods=["GET", "POST"])
def validar_correo():
    error_message = None
    if request.method == "POST":
        codigo_ingresado = request.form["codigo"]

        now = datetime.now(timezone.utc)
        codigo_expiracion = session["codigo_expiracion"]

        # Verificar si el código ha expirado
        if now > codigo_expiracion:
            if session["intentos"] < 2:
                error_message = "El código ha expirado. Se enviará un nuevo código."
                session["codigo"] = random.randint(10000, 99999)
                session["codigo_expiracion"] = datetime.now(timezone.utc) + timedelta(
                    minutes=2
                )
                enviar_codigo(session["email"], session["codigo"])
                session["intentos"] += 1
            else:
                error_message = "El código ha expirado y ya no tienes más intentos."
                return render_template(
                    "validar_correo.html", error_message=error_message
                )
        elif str(codigo_ingresado) == str(session["codigo"]):
            return redirect(url_for("validar_contraseña"))
        else:
            error_message = "Código incorrecto, intenta nuevamente."
    return render_template("validar_correo.html", error_message=error_message)


# Ruta para validar la contraseña
@app.route("/validar_contraseña", methods=["GET", "POST"])
def validar_contraseña():
    error_message = None
    if request.method == "POST":
        password = request.form["password"]
        valid, message = validación_contraseña(password)
        if valid:
            registrar_usuario(
                session["alias"],
                session["email"],
                password,
                session["nombre"],
                session["fecha_nacimiento"],
                session["forma_pago"],
                session["foto_perfil"],
            )
            flash("Usuario registrado correctamente")
            return redirect(url_for("home"))  # Redirigir al inicio de sesión
        else:
            error_message = message
    return render_template("validar_contraseña.html", error_message=error_message)


# Ruta para manejar el inicio de sesión
@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None
    if request.method == "POST":
        alias = request.form["alias"]
        password = request.form["password"]
        usuarios = leer_usuarios()
        print(usuarios)

        for usuario in usuarios:
            if usuario["alias"] == alias and usuario["password"] == password:
                session["user"] = alias
                session["foto_perfil"] = usuario[
                    "foto_perfil"
                ]  # Guardar la foto en la sesión
                if alias == "Admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("user_dashboard"))
        error_message = "Usuario o contraseña incorrectos"
    return render_template("login.html", error_message=error_message)


# Ruta para el panel de administración
@app.route("/admin")
def admin_dashboard():
    # Simular última vez que se cambió la contraseña si no está en la sesión
    if "last_password_change" not in session:
        session["last_password_change"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )

    # Convertir el tiempo guardado en la sesión a datetime
    try:
        last_password_change = datetime.strptime(
            session["last_password_change"], "%Y-%m-%d %H:%M:%S.%f"
        )
    except ValueError:
        # Si la cadena no contiene microsegundos, intenta sin ellos
        last_password_change = datetime.strptime(
            session["last_password_change"], "%Y-%m-%d %H:%M:%S"
        )

    # Verificar si han pasado más de 2 minutos desde el último cambio
    now = datetime.now()
    mostrar_mensaje = False
    if now - last_password_change > PASSWORD_CHANGE_INTERVAL:
        mostrar_mensaje = True

    return render_template(
        "admin.html",
        user=session.get("user", "Admin"),
        user_foto=session.get("user_foto"),
        mostrar_mensaje=mostrar_mensaje,
    )


# Ruta para cambiar la contraseña
@app.route("/actualizar_contraseña", methods=["GET", "POST"])
def actualizar_contrasena():
    if request.method == "POST":
        nueva_contrasena = request.form["new_password"]
        alias = session.get("user", "Admin")

        # Actualizar la contraseña del usuario en el archivo
        actualizar_contraseña_usuario(alias, nueva_contrasena)

        # Actualizar la fecha de cambio de contraseña
        session["last_password_change"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
        flash("Contraseña actualizada exitosamente.")
        return redirect(url_for("admin_dashboard"))
    return render_template("cambiar_contraseña.html")


# Función para actualizar la contraseña del usuario en el archivo
def actualizar_contraseña_usuario(alias, nueva_contraseña):
    try:
        # Leer el archivo JSON existente
        with open(USERS_FILE, "r", encoding='utf-8') as f:
            data = json.load(f)

        # Buscar y actualizar la contraseña del usuario
        usuario_actualizado = False
        for lista_usuarios in [data["administradores"], data["usuarios"]]:
            for usuario in lista_usuarios:
                if usuario["alias"] == alias:
                    usuario["password"] = nueva_contraseña
                    usuario_actualizado = True
                    break
            if usuario_actualizado:
                break

        if not usuario_actualizado:
            flash("Error: No se encontró el usuario.")
            return

        # Escribir los datos actualizados de vuelta al archivo JSON
        with open(USERS_FILE, "w", encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        print(f"Contraseña actualizada para el usuario {alias}")

    except FileNotFoundError:
        flash("Error: No se encontró el archivo de usuarios.")
    except json.JSONDecodeError:
        flash("Error: El archivo de usuarios está corrupto.")
    except Exception as e:
        flash(f"Error al actualizar la contraseña: {str(e)}")


# Ruta para el panel de usuario normal
@app.route("/user")
def user_dashboard():
    if "user" in session and session["user"] != "Admin":
        user_foto = session.get(
            "foto_perfil", None
        )  # Obtener la foto de perfil de la sesión
        return render_template("user.html", user=session["user"], user_foto=user_foto)
    else:
        return redirect(url_for("home"))


# Ruta para el perfil del usuario
@app.route("/perfil")
def perfil():
    if "user" in session:
        # Recuperar los datos del usuario desde la sesión
        alias = session.get("user")
        foto_perfil = session.get("foto_perfil")
        email = session.get("email")  # Asegúrate de que el email esté en la sesión
        nombre = session.get("nombre")
        fecha_nacimiento = session.get("fecha_nacimiento")
        forma_pago = session.get("forma_pago")

        return render_template(
            "perfil.html",
            alias=alias,
            foto_perfil=foto_perfil,
            email=email,
            nombre=nombre,
            fecha_nacimiento=fecha_nacimiento,
            forma_pago=forma_pago,
        )
    else:
        return redirect(url_for("home"))


# Ruta para cerrar sesión
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


# Ruta para explorar
@app.route("/explorar")
def explorar():
    try:
        with open(USERS_FILE, "r", encoding='utf-8') as f:
            data = json.load(f)
            casas = data.get("casas", [])
    except Exception as e:
        print(f"Error al leer el archivo JSON: {e}")
        casas = []
    return render_template("explorar.html", casas=casas)


@app.route("/casa/<int:id>")
def detalles_casa(id):
    try:
        with open(USERS_FILE, "r", encoding='utf-8') as f:
            data = json.load(f)
            casas = data.get("casas", [])
            casa = next((casa for casa in casas if casa["id"] == id), None)
            if casa:
                return render_template("detalles_casa.html", casa=casa)
            else:
                flash("Casa no encontrada")
                return redirect(url_for("explorar"))
    except Exception as e:
        print(f"Error al leer el archivo JSON: {e}")
        flash("Error al cargar los detalles de la casa")
        return redirect(url_for("explorar"))


if __name__ == "__main__":
    app.run(debug=True)
