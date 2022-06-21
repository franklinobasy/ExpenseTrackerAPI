import uuid
from expense_tracker import app
from expense_tracker.models import db, User, Expense
from flask import request, jsonify
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

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