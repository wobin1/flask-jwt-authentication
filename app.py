from flask import Flask, request, json, jsonify
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash 
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config["SECRET_KEY"] = "thisisasecretkey" 


def token_required(f):
	@wraps(f)

	def decorated(*args, **kwargs):
		token = request.args.get('token')

		if not token:
			return "token is missing"
		else:
			data = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")


		return f(*args, **kwargs)	
	return decorated	



def connection():
	connect = psycopg2.connect(
			user = "postgres",
			password = "password",
			host = "localhost",
			port = "5432",
			database = "users"
			)
	return connect

def passwordHash(password):
	hash = generate_password_hash(password)

	return hash

def checkHash(password, _password):
	checkhash = check_password_hash(password, _password)

	return checkhash

@app.route("/register", methods=["POST"])
def register():
	conn = connection()
	cursor = conn.cursor()

	if request.method == "POST":

		try:
			email = request.json['email']
			password = request.json['password']

			_password = passwordHash(password)

			query = "INSERT INTO auth(email, password) VALUES(%s, %s)"
			bind = (email, _password)

			cursor.execute(query, bind)
			conn.commit()
			conn.close()

			return "user details added successfully"
		except:
			return "There was a problem adding user please try again"


	else:
		return "make sure your post method is a POST method"


@app.route("/protected", methods=["POST"])
@token_required
def index():
	return "this is a protected"



@app.route("/login", methods=["POST"])
def login():
	conn = connection()
	cursor = conn.cursor()

	if request.method == "POST":
		mail = request.json['email']
		password = request.json['password']

		query= "SELECT email, password FROM auth WHERE email = %s"
		bind = (mail,)

		cursor.execute(query, bind)
		row = cursor.fetchone()
		_password = row[1]

		if check_password_hash(_password, password):
			token = jwt.encode({'user': mail, 'exp': datetime.datetime.now() + datetime.timedelta(seconds = 20)}, app.config["SECRET_KEY"], algorithm="HS256")
			return jsonify({"token": token})
		else:
			return "password is not correct"
		print(_password) 
		conn.close()

		return ""
	


if __name__ == "__main__":
	app.run(debug=True)