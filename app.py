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
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'clave-secreta-defecto') # En producción, define JWT_SECRET_KEY
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", 'otra-clave-secreta-defecto') # En producción, define SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=60)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    return "Welcome to mini App"


#-----------------------------------------------GET
#-----------------------------------------------POST
#-----------------------------------------------PUT
#-----------------------------------------------DELETE




if __name__ == "__main__":
    app.run(host='localhost', port=5004, debug=True)