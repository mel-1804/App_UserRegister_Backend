from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class Users(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    rut = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cellphone = db.Column(db.Integer, nullable=True)
    password = db.Column(db.String, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
       
    def serialize(self):
        return {
            'id': self.id,
            'rut': self.rut,
            'name': self.name,
            'lastName': self.last_name,
            'email': self.email,
            'cellphone': self.cellphone,
            
        }
