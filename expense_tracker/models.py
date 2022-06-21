from email.policy import default
from expense_tracker import db
from datetime import datetime

class User(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        username = db.Column(db.String(50), unique= True)
        password = db.Column(db.String(50))
        public_id = db.Column(db.String(50))
        expenses = db.relationship('Expense', backref='user')

class Expense(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        description = db.Column(db.Text)
        amount = db.Column(db.Float)
        date = db.Column(db.DateTime, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))