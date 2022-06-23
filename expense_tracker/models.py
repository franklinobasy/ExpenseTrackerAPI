from email.policy import default
from expense_tracker import db
from datetime import datetime

class User(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        username = db.Column(db.String(50), unique= True)
        password = db.Column(db.String(50))
        public_id = db.Column(db.String(50))
        expenses = db.relationship('Expense', backref='user')

        def __repr__(self):
                return f"User <{self.username}>-{self.id}"

class Expense(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        description = db.Column(db.Text)
        amount = db.Column(db.Float)
        date = db.Column(db.DateTime, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

        def __repr__(self):
                return f"{self.description[:20]}... on {self.date.strftime('%c')} by User <{self.user_id}>"