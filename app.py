from datetime import datetime, timedelta
import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import db, Users
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv


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

@app.route('/', methods=['GET'])
def home():
    return "Welcome to mini App"


#GET:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::GET

#This endpoint alows to get the data from all the users, except for passwords--------------------------------
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = Users.query.filter_by(is_active=True).all()
    return jsonify([user.serialize() for user in users]), 200


#POST:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::POST

#This endpoint alows to create a new user-------------------------------------------------------------------test OK
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    existing_user = Users.query.filter(
        (Users.email == data['email']) | (Users.rut == data['rut'])
    ).first()
    if existing_user:
        return jsonify({'msg': 'Usuario ya registrado con ese RUT o email'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = Users(
        rut=data['rut'],
        name=data['name'],
        last_name=data['last_name'],
        email=data['email'],
        cellphone=data.get('cellphone'),
        password=hashed_password
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario registrado exitosamente'}), 201


#This endpoint alows to do login for each user---------------------------------------------------------------test OK
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = Users.query.filter_by(email=data['email']).first()
    if not user or not user.is_active:
        return jsonify({'msg': 'Usuario no existe o está inactivo'}), 401
    if bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': token,
            'user': user.serialize()
        }), 200
    return jsonify({'msg': 'Credenciales incorrectas'}), 401



#PUT:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::PUT

#This endpoint updates the user information, except for the email and rut---------------------------------------
@app.route('/user/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    user = Users.query.get_or_404(id)
    data = request.json
    user.name = data.get('name', user.name)
    user.last_name = data.get('last_name', user.last_name)
    user.cellphone = data.get('cellphone', user.cellphone)
    if 'password' in data:
        user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    db.session.commit()
    return jsonify({'msg': 'Usuario actualizado correctamente'})

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
@app.route('/user/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    user = Users.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario eliminado correctamente'})


if __name__ == "__main__":
    app.run(host='localhost', port=5004, debug=True)