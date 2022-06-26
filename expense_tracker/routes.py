from datetime import datetime, timedelta
from functools import wraps
import uuid
from expense_tracker import app
from expense_tracker.models import db, User, Expense
from flask import make_response, request, jsonify
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

#---- validate token decorator
def validate_token(f):
        @wraps(f)
        def decorator(*args, **kwargs):
                token = None

                if 'access-token' in request.headers:
                        token = request.headers['access-token']

                if not token:
                        return jsonify({"error":"Invalid token, no token"}), 401

                try:
                        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                        current_user = User.query.filter_by(public_id= data['public_id']).first()
                
                except:
                        return jsonify({"error":"Invalid token, decode error"}), 401

                return f(current_user, *args, **kwargs)

        return decorator

@app.route('/api/user', methods=['POST'])
def create_account():
        data = request.get_json()

        if not data:
                return jsonify({'message': 'An error has occured!'}), 400

        if 'username' not in data:
               return jsonify({'message': 'An error has occured!, no username'}), 400

        if 'password' not in data:
                return jsonify({'message': 'An error has occured!, no password'}), 400

        hashed_password = generate_password_hash(data['password'])

        user = User(username= data['username'], password=hashed_password, public_id=str(uuid.uuid4().hex))

        db.session.add(user)
        db.session.commit()

        return jsonify({"message": f"Created Account for {user.username} successfully!"})

@app.route('/api/login', methods=['GET'])
def login():
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
                return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})
        
        user = User.query.filter_by(username= auth.username).first()

        if not user:
                return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})
        
        if check_password_hash(user.password, auth.password):
                token = jwt.encode({"public_id": user.public_id, "exp": datetime.utcnow() + timedelta(minutes=10)}, app.config['SECRET_KEY'])

                return jsonify({"token": token})

        return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})


@app.route('/api/user/', methods=['GET'])
@validate_token
def get_all_user(current_user):
        if current_user.username != 'Admin':
                return jsonify({"message": "Action only accessible to Admin user"})

        users = User.query.all()

        output = list()

        for user in users:
                user_data = dict()
                user_data['id'] = user.id
                user_data['username'] = user.username
                user_data['password'] = user.password
                user_data['public_id'] = user.public_id

                output.append(user_data)

        return jsonify({"users": output})

@app.route('/api/user/1', methods=['GET'])
@validate_token
def get_one_user(current_user):
        
        user = User.query.filter_by(public_id= current_user.public_id).first()

        user_data = dict()
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['public_id'] = user.public_id

        return jsonify({"user": user_data})

@app.route('/api/user/1', methods=['PUT'])
@validate_token
def update_user(current_user):
        data = request.get_json()

        if not data:
                return jsonify({"message": "No information supplied"})

        if 'username' not in data or 'password' not in data:
                return jsonify({"message": "Only username and password can be changed"})

        user = User.query.filter_by(public_id=current_user.public_id).first()

        if not user:
                return jsonify({"message": "Invalid user details"})

        user.username = data['username']

        if data['password']:
                hashed_password = generate_password_hash(data['password'])
                user.password = hashed_password

        db.session.commit()

        return jsonify({"message": "user details changed successfully!"})

@app.route('/api/user/1', methods=['DELETE'])
@validate_token
def delete_user(current_user):
        if current_user.username == 'Admin':
                return jsonify({"message": "Admin cannot be deleted!"})

        db.session.delete(current_user)
        db.session.commit()

        return jsonify({"message": "user deleted successfully!"})

@app.route('/api/expenses', methods=['POST'])
@validate_token
def add_expense(current_user):
        data = request.get_json()
        date= datetime.utcnow()
        if not data:
                return jsonify({"message": "No data found"})

        if 'description' not in data:
                return jsonify({'message': "No description found"})

        if 'amount' not in data:
                return jsonify({"message":"No amount found!"})

        if 'date' in data:
                 date = datetime.strptime(data['date'], r"%d/%m/%Y")

        expense_made = Expense(description= data['description'], amount=data['amount'], user_id=current_user.id, date = date)
        db.session.add(expense_made)
        db.session.commit()

        return jsonify({"success": "expense recorded!"})

@app.route('/api/expenses/1', methods=['GET'])
@validate_token
def get_user_expenses(current_user):
        expenses = Expense.query.filter_by(user_id= current_user.id).all()
        if not expenses:
                return jsonify({"message":"No Expense record found"})

        output = list()
        
        for expense in expenses:
                expense_data=dict()

                expense_data['id'] = expense.id
                expense_data['description']= expense.description
                expense_data['amount'] = expense.amount
                expense_data['date'] = expense.date

                output.append(expense_data)

        return jsonify({"user's expense": output})


@app.route('/api/expenses', methods=['GET'])
@validate_token
def get_all_expenses(current_user):
        if current_user.username != 'Admin':
                return jsonify({"message": "You are not allowed to use this route"})

        expenses = Expense.query.all()
        if not expenses:
                return jsonify({"message":"expense record is empty"})

        output = list()
        
        for expense in expenses:
                expense_data=dict()

                expense_data['id'] = expense.id
                expense_data['description']= expense.description
                expense_data['amount'] = expense.amount
                expense_data['date'] = expense.date
                expense_data['user_id'] = expense.user_id

                output.append(expense_data)

        return jsonify({"expenses": output})


@app.route('/api/expenses/<id>', methods=['DELETE'])
@validate_token
def delete_expense(current_user, id):
        expense = Expense.query.filter_by(id = id, user_id=current_user.id).first()
        if not expense:
                return jsonify({"message":f"No expense with id-{id} found!"})

        db.session.delete(expense)
        db.session.commit()
        return jsonify({"message":"expense deleted successfully."})




