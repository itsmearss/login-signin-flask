from flask import Flask, session, render_template, request, send_file, Response, current_app, make_response, jsonify
from flask_restx import Resource, Api
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from argon2 import PasswordHasher
from datetime import datetime
import random, jwt, pymysql, base64

pymysql.install_as_MySQLdb()

# from model import Users, ArticleHistory, History, Articles, db

# Flask Declaration
app = Flask(__name__)
api = Api(app, title="SpineMotion")
CORS(app)

# Database Connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/dbspinemotion'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT
app.config['JWT_SECRET_KEY'] = 'spinemotion'

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "spinemotionapp@gmail.com"
app.config['MAIL_PASSWORD'] = "ribqqqqfastihnuw"
mail = Mail(app)

# SQLAlchemy
db = SQLAlchemy(app)

# Database Model
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    fullname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    no_hp = db.Column(db.String(14), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    is_verify = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.Date)
    updated_at = db.Column(db.Date)
    
# Register
@api.route('/user/register')
class Registration(Resource):
    # @api.expect(registerParser)
    def post(self):
        args = request.get_json()
        fullname = args['fullname']
        email = args['email']
        no_hp = args['no_hp']
        password = args['password']
        confirm_password = args['confirm_password']
        is_verify = False
        created_at = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        updated_at = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        
        # Next: Password Minimum
        # Confirmation Password Check
        if password != confirm_password:
            return {
                'message': 'Password tidak cocok, cek kembali password nya!',
                'code': 400
            }, 400
        
        # Check Email Already Registered
        user = db.session.execute(db.select(Users).filter_by(email=email)).first()
        if user:
            return {
                'message': 'Email ini telah terdaftar sebelumnya, gunakan email yang lain!'
            }
            
        hashed_password = PasswordHasher().hash(password)
        
        try:
            user = Users(fullname=fullname, email=email, no_hp=no_hp, password=hashed_password, is_verify=False, created_at=created_at, updated_at=updated_at)
            db.session.add(user)
            db.session.commit()
            
            datas = db.session.execute(db.select(Users).filter_by(email=email)).first()
            user_id = datas[0].id
            
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "spinemotion")
            
            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
            
            url = f"http://127.0.0.1:5000/user/verify-account/{email_token}"
            
            data = {
                'name': fullname,
                'url': url
            }
            
            # Verif Email
            sender = "noreply@app.com"
            msg = Message(subject="Verify Your Email - SpineMotion", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)
            
            mail.send(msg)
            return {
                'message': "Berhasil mendaftar, cek email untuk verifikasi"
            }, 201
            
        except Exception as e:
            print(e)
            
            return {
                'message' : f"Error {e}"
            }, 500
            
# Verify Email with Token
@api.route('/user/verify-account/<token>')
class VerifyEmail(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="spinemotion", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()[0]
            
            if not user:
                return {
                    "message": "User not found"
                }, 404
            
            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Akun sudah terevrifikasi sebelumnya'), 400)
                response.headers['Content-Type'] = 'text/html'
                
                return response
            
            user.is_verify = True
            db.session.commit()
            
            response = make_response(render_template('response.html', success=True, message='Berhasil verifikasi, silahkan login ke SpineMotion App'), 400)
            response.headers['Content-Type'] = 'text/html'
            
            return response
        
        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired"}, 401
        
        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token"}, 401
        
        except Exception as e:
            return {"message": f"Error {e}"}, 500
        
# Login
@api.route('/user/login')
class Login(Resource):
    def post(self):
        base64Str = request.headers.get('Authorization')
        base64Str = base64Str[6:]
        
        base64Bytes = base64Str.encode('ascii')
        messageBytes = base64.b64decode(base64Bytes)
        pair = messageBytes.decode('ascii')
        
        email, password = pair.split(":")
        
        if not email or not password:
            return {"message": "Please type email and password"}, 400
        
        user = db.session.execute(db.Select(Users).filter_by(email=email)).first()
        
        if not user:
            return {"message": "User not found, please do register"}, 400
        
        if not user[0].is_verify:
            return {"message": "Account not activated, check email for verify"}, 401
        
        if PasswordHasher().verify(user[0].password, password):
            payload = {
                'id': user[0].id,
                'fullname': user[0].fullname,
                'email': user[0].email
            }
        
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "spinemotion")
            
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
            
            return { 
                    'token': token,
                    'status': 'success'}, 200
        else:
            return { 
                    'message': 'Wrong password',
                    'status': 'failed' 
                    }, 400

# User is currently logged in
@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="spinemotion", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(Users).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404
            
            user = user[0]
            
            return {
                'status': 'Success',
                'data': {
                    'id': user.id,
                    'fullname': user.fullname,
                    'email': user.email,
                    'no_hp': user.no_hp
                }
            }, 200
        
        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401
        
        except jwt.InvalidTokenError:
            return {'messge': 'Invalid token'}, 401

@app.route('/')
def index():
    return "<p>Hello Dunia!</p>"

if __name__ == '__main__':
    app.run(debug=True)