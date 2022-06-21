from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

#----- configurations
app.config.from_pyfile('./config.py')

#----- integrate app into sqlalchemy
db = SQLAlchemy(app)

from expense_tracker import routes