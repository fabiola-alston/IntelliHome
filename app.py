from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
)
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
app.config["JSON_AS_ASCII"] = False
# Definir un tiempo límite para el cambio de contraseña (2 minutos)
PASSWORD_CHANGE_INTERVAL = timedelta(minutes=2)


# Función para leer usuarios desde el archivo JSON
def leer_usuarios():
    usuarios = []
    administradores = []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
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
                "metodos_pago",
                "foto_perfil",
                "casas",
            ]
            return all(field in usuario.keys() for field in required_fields)

        # Verificar campos para usuarios y administradores
        usuarios = [u for u in usuarios if verificar_campos(u)]
        administradores = [a for a in administradores]

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
        with open(USERS_FILE, "r+", encoding="utf-8") as f:
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
        with open(USERS_FILE, "w", encoding="utf-8") as f:
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
def validacion_contrasena(password):
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
def enviar_mensaje(email, codigo, message=None):
    sender_email = "intellihome.playitaiguana@gmail.com"
    sender_password = "feum sttx vaqc peip"

    msg = EmailMessage()
    msg_content = ""
    if not message:
        msg_content = f"""
    Estimado usuario,

    Saludos desde Intelli Home. A continuación, le proporcionamos su código de verificación:

    Código de verificación: {codigo}

    Por favor, ingrese este código en la página de verificación para completar su registro.

    ¡Gracias por confiar en nosotros!

    Atentamente,
    El equipo de Intelli Home.
        """
    else:
        msg_content = message

    msg.set_content(msg_content)

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
                filename = secure_filename(
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

        enviar_mensaje(email, session["codigo"])

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
                enviar_mensaje(session["email"], session["codigo"])
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
        valid, message = validacion_contrasena(password)
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
                if is_admin(alias):
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
        with open(USERS_FILE, "r", encoding="utf-8") as f:
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
        with open(USERS_FILE, "w", encoding="utf-8") as f:
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
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        usuario_actual = None
        for lista_usuarios in [data["administradores"], data["usuarios"]]:
            for usuario in lista_usuarios:
                if usuario["alias"] == session["user"]:
                    usuario_actual = usuario
                    break
            if usuario_actual:
                break

        # Obtener las casas usando las IDs
        casas_alquiladas_ids = usuario_actual.get("casas", [])
        casas_alquiladas = [
            casa for casa in data["casas"] if casa["id"] in casas_alquiladas_ids
        ]

        return render_template(
            "user.html", user=session["user"], casas=casas_alquiladas
        )
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
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            casas = data.get("casas", [])

            for casa in casas:
                if len(casa["calificacion"]) > 0:
                    casa["rating_promedio"] = sum(
                        calificacion["rating"] for calificacion in casa["calificacion"]
                    ) / len(casa["calificacion"])
                else:
                    casa["rating_promedio"] = 0

    except Exception as e:
        print(f"Error al leer el archivo JSON: {e}")
        casas = []
    return render_template("explorar.html", casas=casas)


@app.route("/casa/<int:id>")
def detalles_casa(id):
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
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


@app.route("/actualizar_perfil", methods=["POST"])
def actualizar_perfil():
    if "user" not in session:
        return redirect(url_for("home"))

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        for lista_usuarios in [data["administradores"], data["usuarios"]]:
            for usuario in lista_usuarios:
                if usuario["alias"] == session["user"]:
                    # Actualizar campos
                    usuario["nombre"] = request.form["nombre"]
                    usuario["alias"] = request.form["alias"]
                    usuario["fecha_nacimiento"] = request.form["fecha_nacimiento"]
                    usuario["forma_pago"] = request.form["forma_pago"]

                    # Manejar la actualización de la foto de perfil
                    if "foto_perfil" in request.files:
                        file = request.files["foto_perfil"]
                        if file.filename != "":
                            filename = secure_filename(
                                f"{usuario['alias']}.{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename}"
                            )
                            file.save(
                                os.path.join(app.config["UPLOAD_FOLDER"], filename)
                            )
                            usuario["foto_perfil"] = filename

                    # Manejar la actualización de la contraseña
                    new_password = request.form["password"]
                    if new_password:
                        if new_password == request.form["confirm_password"]:
                            usuario["password"] = new_password
                        else:
                            flash("Las contraseñas no coinciden")
                            return redirect(url_for("user_dashboard"))

                    # Actualizar la sesión
                    session["nombre"] = usuario["nombre"]
                    session["alias"] = usuario["alias"]
                    session["fecha_nacimiento"] = usuario["fecha_nacimiento"]
                    session["forma_pago"] = usuario["forma_pago"]
                    session["foto_perfil"] = usuario["foto_perfil"]

                    # Guardar los cambios en el archivo JSON
                    with open(USERS_FILE, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=4)

                    flash("Perfil actualizado con éxito")
                    return redirect(url_for("user_dashboard"))

        flash("Usuario no encontrado")
        return redirect(url_for("user_dashboard"))

    except Exception as e:
        print(f"Error al actualizar el perfil: {e}")
        flash("Ocurrió un error al actualizar el perfil")
        return redirect(url_for("user_dashboard"))


@app.route("/alquilar_casa/<int:id>", methods=["POST"])
def alquilar_casa(id):
    if "user" not in session:
        flash("Debes iniciar sesión para alquilar una casa.")
        return redirect(url_for("home"))

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Buscar la casa por ID
        casa = next((casa for casa in data["casas"] if casa["id"] == id), None)
        if not casa:
            flash("Casa no encontrada.")
            return redirect(url_for("explorar"))

        # Verificar si la casa ya está alquilada
        if casa["inquilinos"]:
            flash("Esta casa ya está alquilada.")
            return redirect(url_for("detalles_casa", id=id))

        # Buscar al usuario actual
        usuario_actual = next(
            (u for u in data["usuarios"] if u["alias"] == session["user"]), None
        )
        if not usuario_actual:
            flash("Usuario no encontrado.")
            return redirect(url_for("explorar"))

        # Agregar la casa a la lista de casas del usuario
        if "casas" not in usuario_actual:
            usuario_actual["casas"] = []


        usuario_actual["casas"].append(id)  # Usar ID de la casa

        # Agregar al usuario como inquilino de la casa
        casa["inquilinos"].append(session["user"])

        # Guardar los cambios en el archivo JSON
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        flash(f"Has alquilado exitosamente la casa: {casa['nombre']}")
        return redirect(url_for("user_dashboard"))

    except Exception as e:
        print(f"Error al alquilar la casa: {e}")
        flash("Ocurrió un error al intentar alquilar la casa.")
        return redirect(url_for("explorar"))


@app.route("/autorizar_inquilino/<int:casa_id>", methods=["POST"])
def autorizar_inquilino(casa_id):
    if "user" not in session:
        return jsonify({"error": "Debes iniciar sesión para autorizar inquilinos."})

    nuevo_inquilino = request.form.get("nuevo_inquilino")

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Buscar la casa por ID
        casa = next((casa for casa in data["casas"] if casa["id"] == casa_id), None)
        if not casa:
            return jsonify({"error": "Casa no encontrada."})

        # Buscar al nuevo inquilino en la lista de usuarios
        nuevo_usuario = next(
            (u for u in data["usuarios"] if u["alias"] == nuevo_inquilino), None
        )
        if not nuevo_usuario:
            return jsonify({"error": f"El usuario {nuevo_inquilino} no existe."})

        # Verificar si el nuevo inquilino ya es inquilino de la casa
        if nuevo_inquilino in casa["inquilinos"]:
            return jsonify(
                {"error": f"{nuevo_inquilino} ya es inquilino de esta casa."}
            )

        # Agregar el nuevo inquilino a la casa
        casa["inquilinos"].append(nuevo_inquilino)

        # Agregar la casa a la lista de casas del nuevo inquilino
        if "casas" not in nuevo_usuario:
            nuevo_usuario["casas"] = []
        nuevo_usuario["casas"].append(casa_id)  # Usar ID de la casa

        # Guardar los cambios en el archivo JSON
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        return jsonify(
            {"success": f"{nuevo_inquilino} ha sido autorizado como inquilino."}
        )
    except Exception as e:
        print(f"Error al autorizar inquilino: {e}")
        return jsonify({"error": "Ocurrió un error al autorizar al inquilino."})


# Lee info de pagos desde el archivo JSON
def leer_info_pagos(username):
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for user in data["usuarios"]:
                if user["alias"] == username:
                    return user.get("metodos_pago", [])
    except FileNotFoundError:
        print("Archivo no encontrado :(")
    return None


# Guarda información de pago en el archivo JSON
def guardar_info_pago(
    username, card_number, card_holder, date, pin, brand, debt, amount
):
    try:
        with open(USERS_FILE, "r+", encoding="utf-8") as f:
            data = json.load(f)
            user_found = False
            for user in data["usuarios"]:
                if user["alias"] == username:
                    user_found = True
                    if "metodos_pago" not in user:
                        user["metodos_pago"] = []
                    user["metodos_pago"].append(
                        {
                            "card_number": card_number,
                            "card_holder": card_holder,
                            "date": date,
                            "pin": pin,
                            "brand": brand,
                            "debt": float(debt),
                            "amount": float(amount),
                        }
                    )
                    break
            if not user_found:
                nuevo_usuario = {
                    "alias": username,
                    "metodos_pago": [
                        {
                            "card_number": card_number,
                            "card_holder": card_holder,
                            "date": date,
                            "pin": pin,
                            "brand": brand,
                            "debt": float(debt),
                            "amount": float(amount),
                        }
                    ],
                }
                data["usuarios"].append(nuevo_usuario)
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
    except FileNotFoundError:
        # Si el archivo no existe, crearlo y agregar el primer usuario
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            data = {
                "usuarios": [
                    {
                        "alias": username,
                        "metodos_pago": [
                            {
                                "card_number": card_number,
                                "card_holder": card_holder,
                                "date": date,
                                "pin": pin,
                                "brand": brand,
                                "debt": float(debt),
                                "amount": float(amount),
                            }
                        ],
                    }
                ]
            }
            json.dump(data, f, indent=4)


@app.route('/agregar_pago', methods=['GET', 'POST'])
def agregar_pago():
    if request.method == 'POST':
        # Aquí puedes manejar el envío del formulario para guardar el método de pago
        card_number = request.form['card_number']
        card_holder = request.form['card_holder']
        month = request.form['month']
        year = request.form['year']
        pin = request.form['pin']
        # Lógica para determinar la marca de la tarjeta
        brand = request.form['brand']

        if brand.lower() not in ["visca", "masterchef", "americancity", "ticaplay"]:
            flash("Marca de tarjeta no válida")
            return redirect(url_for('agregar_pago'))

        print(
            card_number.isdigit(),
            len(card_number) == 16,
            card_holder.isalpha(),
            len(card_holder) > 0,
            month.isdigit(),
            1 <= int(month) <= 13,
            year.isdigit(),
            len(year) == 2,
            pin.isdigit(),
            3 <= len(pin) <= 4,
            brand.lower() == "visca" and card_number.startswith("1"),
            brand.lower() == "masterchef" and card_number.startswith("2"),
            brand.lower() == "americancity" and card_number.startswith("3"),
            brand.lower() == "ticaplay" and card_number.startswith("4"),
        )

        if not (
            card_number.isdigit()
            and len(card_number) == 16
            and card_holder.isalpha()
            and len(card_holder) > 0
            and month.isdigit()
            and 1 <= int(month) <= 13
            and year.isdigit()
            and len(year) == 2
            and pin.isdigit()
            and 3 <= len(pin) <= 4
            and (
                brand.lower() == "visca" and card_number.startswith("1") 
                or brand.lower() == "masterchef" and card_number.startswith("2")
                or brand.lower() == "americancity" and card_number.startswith("3")
                or brand.lower() == "ticaplay" and card_number.startswith("4")
            )
        ):
            flash("Por favor, ingresa información válida")
            return redirect(url_for('agregar_pago'))
        # Chequea que la fecha de expiración sea válida
        current_month = datetime.now().month
        current_year = datetime.now().year % 100 
        if int(year) < current_year or (int(year) == current_year and int(month) < current_month):
            flash("La tarjeta ha expirado")
            return redirect(url_for('agregar_pago'))

        # Guardar el método de pago
        username = session['user']
        # Guardar el método de pago
        guardar_info_pago(username, card_number, card_holder, f"{month}/{year}", pin, brand, 0, 0) 
    return render_template('agregar_pago.html')


@app.route('/add_house', methods=['POST'])
def add_house():
    # Obtener datos del formulario
    capacity = request.form['capacity']
    rooms = request.form['rooms']
    bathrooms = request.form['bathrooms']
    amenities = request.form['amenities']
    features = request.form['features']
    other_features = request.form['other-features']
    address = request.form['address']
    coordinates = request.form['coordinates']
    # Manejo de la carga de fotos
    photos = request.files.getlist('photos')
    photo_paths = []
    for photo in photos:
        if photo:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
            photo.save(photo_path)
            photo_paths.append(photo_path)

    # Cargar datos en el archivo JSON
    with open('usuarios.json', 'r+') as file:
        data = json.load(file)
        new_house = {
            "id": len(data['casas']) + 1,  # Asignar un nuevo ID
            "nombre": address, 
            "ubicacion": address,
            "precio": 0,  
            "calificacion": [],
            "imagen": photo_paths[0],  # Guarda las rutas de las imágenes
            "imagenes": photo_paths,
            "inquilinos": [],
            "capacidad": capacity,
            "habitaciones": rooms,
            "banos": bathrooms,
            "amenidades": amenities,
            "caracteristicas_generales": features,
            "otras_caracteristicas": other_features,
            "coordenadas": coordinates
        }
        data['casas'].append(new_house)
        file.seek(0)
        json.dump(data, file, indent=4)
        file.truncate()

    return jsonify({"message": "Casa agregada exitosamente!"}), 201


@app.route('/casas')
def casas():
    with open('usuarios.json', 'r') as file:
        data = json.load(file)
    return render_template('casas.html', casas=data['casas'])


# Cambia el nombre de la función para evitar conflictos
@app.route('/inactive_houses')
def list_inactive_houses():
    with open('usuarios.json', 'r') as file:
        data = json.load(file)
    # Filtrar casas inactivas
    inactive_houses = [house for house in data['casas'] if not house.get('disponible', True)]
    return render_template('admin.html', inactive_houses=inactive_houses)


# Ruta para cambiar el estado de la casa a disponible
@app.route('/set_available/<int:house_id>', methods=['GET'])
def set_available(house_id):
    with open('usuarios.json', 'r+') as file:
        data = json.load(file)
        # Buscar la casa por ID y cambiar su estado
        for house in data['casas']:
            if house['id'] == house_id:
                house['disponible'] = True  # Cambiar el estado a disponible
                break
        # Guardar los cambios en el archivo JSON
        file.seek(0)
        json.dump(data, file, indent=4)
        file.truncate()
    flash("La casa ha sido marcada como disponible.", "success")
    return redirect(url_for('list_inactive_houses'))  # Redirigir a la lista de casas inactivas


def is_admin(user):
    with open('usuarios.json', 'r') as file:
        data = json.load(file)
    return user in [admin['alias'] for admin in data['administradores']]


@app.route('/promocionar', methods=['POST'])
def promocionar():
    if not is_admin(session.get('user')):
        return redirect(url_for('home'))

    if request.method == 'POST':
        alias = request.form['alias']
        user_data = {}
        user_email = ""
        with open('usuarios.json', 'r+') as file:
            data = json.load(file)
            for user in data['usuarios']:
                if user['alias'] == alias:
                    user_data = user
                    break

            user_email = user_data['email']
            session['promocionando'] = True

            # Enviar un correo al usuario para confirmar la promoción
            enviar_mensaje(
                user_email,
                0,
                message= f"""
¡Felicidades! Has sido promocionado a administrador.
Confirma la promocion entrando al siguiente link: http://localhost:5000/confirmar_promocion
                """
            )
        return redirect(url_for('admin_dashboard'))


@app.route('/confirmar_promocion', methods=['POST', 'GET'])
def confirmar_promocion():
    """
    Esta ruta la abre al usuario. En la funcion promocionar, se le 
    envia un link a esta ruta para que el usuario confirme su promocion.
    Muestra un mensaje de exito si el usuario confirma su promocion.
    """
    if is_admin(session.get('user')) or not session.get('promocionando'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        user_data = {}
        user_alias = request.form['alias']

        with open('usuarios.json', 'r+') as file:
            data = json.load(file)
            for user in data['usuarios']:
                if user['alias'] == user_alias:
                    user_data = user
                    break

            data["administradores"].append(user_data)
            del data["usuarios"][data["usuarios"].index(user_data)]
            file.seek(0)
            json.dump(data, file, indent=4)
            file.truncate()

        return redirect(url_for('promocion_confirmada'))

    if request.method == 'GET':
        return render_template('confirmar_promocion.html', alias=session.get('user'))


@app.route('/promocion_confirmada', methods=['POST', 'GET'])
def promocion_confirmada():
    flash("¡Felicidades! Has sido promocionado a administrador.", "success")
    return redirect(url_for('user_dashboard'))


@app.route('/eliminar_admin', methods=['POST', 'GET'])
def eliminar_admin():
    if not is_admin(session.get('user')):
        return redirect(url_for('home'))
    alias = request.form['alias']
    user_data = {}
    with open('usuarios.json', 'r+') as file:
        data = json.load(file)
        for user in data['administradores']:
            if user['alias'] == alias:
                user_data = user
                break
        else:
            flash("Usuario no encontrado", "error")
            return redirect(url_for('admin_dashboard'))

        data["usuarios"].append(user_data)
        del data["administradores"][data["administradores"].index(user_data)]
        file.seek(0)
        json.dump(data, file, indent=4)
        file.truncate()

    return redirect(url_for('admin_dashboard'))


if __name__ == "__main__":
    app.run(debug=True)
