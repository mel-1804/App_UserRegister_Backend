from datetime import datetime, timedelta
import os
import re
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import db, Users
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mibasededatos.db'
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'clave-secreta-defecto') # In production, define JWT_SECRET_KEY
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", 'otra-clave-secreta-defecto') # In production, define SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=60)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

email_regex = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')

@app.route('/', methods=['GET'])
def home():
    return "Welcome to mini App"


#GET:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::GET

#This endpoint alows to get the data from all the users, except for passwords-------------------------------TESTED OK
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user = get_jwt_identity()

    users = Users.query.filter_by(is_active=True).all()
    serialized_users = [user.serialize() for user in users]

    return jsonify(serialized_users), 200


#POST:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::POST

#This endpoint alows to create a new user-------------------------------------------------------------------TESTED OK
@app.route('/register', methods=['POST'])
def register():
    data = request.json

     # Validate email format
    email = data.get('email', '')
    if not email or not email_regex.match(email):
        return jsonify({'msg': 'Correo electrónico no es válido'}), 400
    
    # Validate password length
    password = data.get('password', '')
    if not password or len(password) < 6 or len(password) > 10:
        return jsonify({'msg': 'La contraseña debe tener entre 6 y 10 caracteres'}), 400

    # Check if email is already registered
    if Users.query.filter_by(email=email).first():
        return jsonify({'msg': 'Ya existe un usuario registrado con este correo electrónico'}), 400

    # Checks if RUT is already registered
    if Users.query.filter_by(rut=data.get('rut')).first():
        return jsonify({'msg': 'Ya existe un usuario registrado con este RUT'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Create and store the user
    user = Users(
        rut=data['rut'],
        name=data['name'],
        last_name=data['lastName'],
        email=data['email'],
        cellphone=data.get('cellphone'),
        password=hashed_password,
        is_active=True
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario registrado exitosamente'}), 201


#This endpoint alows to do login for each user---------------------------------------------------------------TESTED OK
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = Users.query.filter_by(email=data['email']).first()
    if not user or not user.is_active:
        return jsonify({'msg': 'Usuario no existe o está inactivo'}), 401
    if bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({
            'access_token': token,
            'user': user.serialize()
        }), 200
    return jsonify({'msg': 'Credenciales incorrectas'}), 401



#PUT:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::PUT

#This endpoint updates the user information, except for the email and rut---------------------------------------TESTED OK
@app.route('/updateUser/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    user = db.session.get(Users, id)
    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    data = request.get_json()
    if data is None:
        return jsonify({"message": "JSON inválido o no recibido"}), 400
   
    name = data.get("name")
    last_name = data.get("lastName")
    cellphone = data.get("cellphone")
    password = data.get("password")

    if name:
        user.name = name
    if last_name:
        user.last_name = last_name
    if cellphone:
        user.cellphone = cellphone
    if password:
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.session.commit()

    return jsonify({"message": "Usuario actualizado correctamente"}), 200


#This endpoint just deactivates the user, recommended for production as "DELETE USER"----------------------------
@app.route('/user/<int:id>/deactivate', methods=['PUT'])
@jwt_required()
def deactivate_user(id):
    user = Users.query.get_or_404(id)
    user.is_active = False
    db.session.commit()
    return jsonify({'msg': 'Usuario desactivado correctamente'})


#DELETE:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::DELETE

#This endopoint really deletes the user, not recommended for production-----------------------------------------
@app.route('/deleteUser/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    user = Users.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario eliminado correctamente'})


if __name__ == "__main__":
    app.run(host='localhost', port=5004, debug=True)