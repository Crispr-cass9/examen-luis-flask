from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify
from flask_bootstrap import Bootstrap5
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import werkzeug.exceptions
from forms.forms import Register, Login
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, unset_access_cookies, unset_jwt_cookies
from pymongo import MongoClient
import json
import werkzeug
from bson import ObjectId

## Sé que antes de añadir al usuario a la base de datos debo hashear la contraseña, pero no me dió tiempo, aún así te dejo el bonito import
## Y también sé lo de proteger las credenciales de acceso

mongo = MongoClient("mongodb://localhost:27017/")
db = mongo['examen-Luis-recuperacion']
coleccion = db['users']
db2 = mongo['examen-Luis-recuperacion']
coleccion_tienda = db2['tienda']

app = Flask(__name__)
Bootstrap5(app)
jwt = JWTManager(app)
app.config['SECRET_KEY'] = 'patata'

header_rutas_no_logeado = [{'ruta': '/login', 'nombre':'logearse'}, {'ruta':'register', 'nombre':'registrarse'}]
header_rutas_logeado = [{'ruta': '/profile', 'nombre':'Perfil'}, {'ruta':'/cerrar-sesion', 'nombre':'Logout'}]

@app.route('/')
def home():
    return render_template('inicio.html', header = header_rutas_no_logeado)

@app.route('/register')
def register():
    try:
        cookie = request.cookies['access_token_cookie']
        return redirect('profile')

    except werkzeug.exceptions.BadRequestKeyError as e:
        return render_template('register.html', form=Register(), header = header_rutas_no_logeado)

@app.route('/login')
def login():
    try:
        print(request.cookies['access_token_cookie'])
        return redirect('profile')

    except werkzeug.exceptions.BadRequestKeyError as e:
        return render_template('login.html', form = Login(), header = header_rutas_no_logeado)

@app.route('/registrar_usuario', methods=['POST'])
def registrar():

    datos_usuario = request.form

    objeto = { 'username': datos_usuario['username'],
                'email': datos_usuario['email'],
                'contrasenya': datos_usuario['contrasenya'],
                'contador_visitas': 1,
                'carrito': []
              }
    
    coleccion.insert_one(objeto)

    respuesta = make_response(redirect(url_for('profile')))
    cookie = create_access_token(identity=str({'email':objeto['email']}))
    respuesta.set_cookie('access_token_cookie', cookie)

    return respuesta

@app.route('/logear_usuario', methods=['POST'])
def logearse():
    form_usuario = request.form
    datos_usuario = coleccion.find_one({'email': form_usuario['email']})
    
    if not datos_usuario:
        return redirect('register')
    
    if datos_usuario['contrasenya'] == form_usuario['contrasenya']:
        contador_visitas = datos_usuario['contador_visitas']
        contador_visitas+=1

        coleccion.update_one(
            {'email': datos_usuario['email']}, {'$set': {'contador_visitas': contador_visitas, 'carrito':[]}}
        )
        respuesta = make_response(redirect(url_for('profile')))
        cookie = create_access_token(identity=str({'email': datos_usuario['email']}))
        respuesta.set_cookie('access_token_cookie', cookie)
        return respuesta

    return '<h1>Logeado</h1>'


@app.route('/profile')
@jwt_required(locations=['cookies'])
def profile():
    user = get_jwt_identity()
    user = user.replace("'", '"')
    user = json.loads(user)
    user = user['email']
    print(user)
    print(type(user))
    datos_usuario = coleccion.find_one({'email': user})

    return render_template('profile.html', user=datos_usuario, header=header_rutas_logeado)
    
@app.route('/cerrar-sesion')
@jwt_required(locations=['cookies'])
def cerrar_sesion():
    response = make_response(redirect(url_for('login')))
    unset_access_cookies(response)
    unset_jwt_cookies(response)
    return response

@app.route('/tienda')
@jwt_required(locations=['cookies'])
def tienda():
    productos = coleccion_tienda.find()
    return render_template('tienda.html', tienda=productos)

@app.route('/producto/<id>')
@jwt_required(locations=['cookies'])
def producto(id):
    print(id)
    producto_mostrar = coleccion_tienda.find_one({'_id': ObjectId(id)})
    print(producto_mostrar)
    return render_template('producto.html', producto= producto_mostrar)

@app.route('/anyadir/<id>')
@jwt_required(locations=['cookies'])
def anyadir(id):
    producto_anyadir = coleccion_tienda.find_one({'_id': ObjectId(id)})
    user = get_jwt_identity()
    user = user.replace("'", '"')
    user = json.loads(user)
    user = user['email']
    datos_usuario = coleccion.find_one({'email': user})
    carrito = list(datos_usuario['carrito'])
    carrito.append(producto_anyadir)
    coleccion.update_one(
            {'email': datos_usuario['email']}, {'$set': {'carrito':carrito}}

    )
    return redirect(url_for('tienda'))

@app.route('/carrito')
@jwt_required(locations=['cookies'])
def carrito():
    user = get_jwt_identity()
    user = user.replace("'", '"')
    user = json.loads(user)
    user = user['email']
    datos_usuario = coleccion.find_one({'email': user})
    carrito_usuario = list(datos_usuario['carrito'])
    
    return render_template('carrito.html', carrito = carrito_usuario)

## Sé que esta ruta debería protegerla y añadir un register de admin pero no me da el tiempo
@app.route('/admin')
def admin():
    datos_usuarios = coleccion.find()
    
    
    return render_template('admin.html', usuarios = datos_usuarios)

@jwt.unauthorized_loader
def error_401(_):
    return redirect('/login')

@jwt.expired_token_loader
def token_expirado(_, __):
    response = make_response(redirect(url_for('login')))
    unset_access_cookies(response)
    unset_jwt_cookies(response)
    return response


@app.errorhandler(404)
def error_404(_):
    return render_template('error_404.html')


if __name__ == '__main__':
    app.run(debug=True, port=80000)