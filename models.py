from flask_sqlalchemy import SQLAlchemy

class Users(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    rut = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    cellphone = db.Column(db.Integer, nullable=True)
    password = db.Column(db.String, nullable=False)
    
       
    def serialize(self):
        return {
            'id': self.id,
            'rut': self.rut,
            'name': self.name,
            'lastName': self.last_name,
            'email': self.email,
            'cellphone': self.cellphone,
            
        }
