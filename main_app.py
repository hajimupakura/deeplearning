# import the necessary packages
# from keras.preprocessing import image
from keras.preprocessing.image import img_to_array, load_img
from keras.applications import imagenet_utils
from keras.applications.inception_v3 import InceptionV3, preprocess_input
from PIL import Image
import numpy as np
import settings
import helpers
import flask
import redis
import uuid
import time
import json
import io

# import Flask related packages for user management and authentication
from flask import Flask, render_template, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, auth_token_required, utils, current_user

from flask_security.decorators import http_auth_required
from flask import jsonify, request, abort

from functools import wraps
# from flask_login import login_user, logout_user, current_user # flask_logins implementations of login_user, logout_user, current_user seem more seamless

from flask_cors import CORS, cross_origin
# from flask_login import LoginManager
from itsdangerous import URLSafeTimedSerializer
# initialize our Flask application and Redis server
app = flask.Flask(__name__)
redis_db = redis.StrictRedis(host=settings.REDIS_HOST,
	port=settings.REDIS_PORT, db=settings.REDIS_DB)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_PASSWORD_SALT'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SECURITY_TOKEN_AUTHENTICATION_KEY'] = 'token'
login_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

cors = CORS(app, resources={r"/api/*": {"origins": "http://localhost:8100"}})

# login = LoginManager(app)
# Create database connection object
db = SQLAlchemy(app)

# Define models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    token = db.Column(db.String(255))
    api_key = db.Column(db.String(255))
    is_logged_in = db.Column(db.Boolean())
    first_name = db.Column(db.String(80))
    surname = db.Column(db.String(80))
    occupation = db.Column(db.String(80))
    country = db.Column(db.String(80))
    
    def __str__(self):
        return "id: " + str(self.id) + ", email: " + self.email + ", is_authenticated: " +  str(self.is_authenticated)
               

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
max_age = 600
# Create a user to test with
@app.before_first_request
def create_user():
    print(' ')
    db.create_all()
    user_datastore.create_user(email='test@drcadx.com', password='jnxlQZ^FW^k1i6d', is_logged_in=0, active=0, confirmed_at=None, roles=[], token=None, api_key=None, first_name='John', surname='Doe', occupation='Programmer', country='Zimbabwe')
    db.session.commit()

# @login.user_loader
# def load_user(id):
#     user = User.query.get(int(id))
#     print("load_user")
#     return user

# The actual decorator function
def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        try:
            token = request.args.get('token');

            serializer = current_app.extensions['security'].remember_token_serializer
            data = serializer.loads(token)
            user_id = data[0]
            #Find the User
            user = User.query.filter_by(id=user_id).first()
            stored_token = user.token
            print(stored_token)

            if request.args.get('token') and request.args.get('token') == stored_token:
                return view_function(*args, **kwargs)
            else:
                abort(401)
        except Exception:
            print(Exception)
            abort(401)
    return decorated_function
    
@app.route('/api/login', methods=['POST'])
@cross_origin() 
def dummyAPI():
    
    json_data = request.json
#     print (json_data)
    user = json_data['username']
    password = json_data['password']
    
    user = User.query.filter_by(email=user).first()
    status = utils.verify_password(password, user.password)
    token = None
    
    if status:
#         print (current_user)
        utils.login_user(user, remember=True)
#         print (current_user)
        token = user.get_auth_token()
        user.token = token
        user.is_logged_in = True;
        print(user.token)
        db.session.commit()
        
    response_dict = {
        "success": status,
        "username": user.email,
        "token": token
    }
    
    return jsonify(response_dict)

# @app.route('/api/login', methods=['GET'])
# @cross_origin() 
# @http_auth_required
# def dummyAPI():
     
#     user = request.authorization.username
#     password = request.authorization.password
    
#     user = User.query.filter_by(email=user).first()
#     login_user(user)
#     token = user.get_auth_token()
#     print(token)
    
#     response_dict = {
#         "success": True,
#         "username": user.email,
#         "token": token
#     }
#     return jsonify(response_dict)

@app.route('/api/is_logged_in')
@cross_origin() 
@auth_token_required #will validate non-expired tokens
def isactive():
#     status = current_user.is_authenticated #This is always true if @auth_token_required is used, so won't use it
#     print(status)
    
     #Decrypt the Security Token, data = [username, hashpass]
#         data = login_serializer.loads(token, max_age=utils.LOGIN)
#         print(utils.get_token_status(token, 'login', max_age='LOGIN', return_data=True))

    token = request.args.get('token')
    serializer = current_app.extensions['security'].remember_token_serializer
    data = serializer.loads(token)
    user_id = data[0]
    #Find the User
    user = User.query.filter_by(id=user_id).first()
    stored_token = user.token
    status = (token == stored_token) and user.is_logged_in

    return jsonify({
        "success": True,
        "is_logged_in": status
    })

# @app.route('/api/is_logged_in')
# @cross_origin() 
# # @auth_token_required
# def isactive():
#     status = current_user.is_authenticated
#     print(status)
    
#     return jsonify({
#         "success": True,
#         "is_logged_in": status
#     })

@app.route('/api/logout')
def log_out():
    utils.logout_user()
    
    token = request.args.get('token');
        
    serializer = current_app.extensions['security'].remember_token_serializer
    data = serializer.loads(token)
    user_id = data[0]
    #Find the User
    user = User.query.filter_by(id=user_id).first()
        
    user.token = None
    user.is_logged_in = False;
    
    db.session.commit()
    status = True
    return jsonify({
        "success": status
    })

# @app.route('/api/logout')
# def log_out():
#     utils.logout_user()
#     status = True
#     return jsonify({
#         "success": status
#     })


@app.route('/api/testtoken')
@cross_origin() 
@require_appkey
def testtoken():
    status = current_user.is_authenticated
    print(status)
    
    return jsonify({
        "success": True,
        "is_logged_in": status
    })
    
def prepare_image(test_image, target):
	# if the image mode is not RGB, convert it
	if test_image.mode != "RGB":
		test_image = test_image.convert("RGB")

	# resize the input image and preprocess it
# 	image = image.resize(target)
# 	image = img_to_array(image)
# 	image = np.expand_dims(image, axis=0)
# 	image = imagenet_utils.preprocess_input(image)
    
	test_image = test_image.resize(target)
	test_image = img_to_array(test_image)
	test_image = np.expand_dims(test_image, axis=0)
	test_image = preprocess_input(test_image)

	# return the processed image
	return test_image

@app.route("/")
def homepage():
	return "***"

@app.route("/api/predict", methods=["POST"])
@cross_origin() 
@require_appkey
def predict():
	# initialize the data dictionary that will be returned from the
	# view
	data = {"success": False}

	# ensure an image was properly uploaded to our endpoint
	if flask.request.method == "POST":
		if flask.request.files.get("image") or flask.request.json.get('image'):
			print('got image')
			if flask.request.files.get("image"):
				# read the image in PIL format and prepare it for
				# classification
				test_image = flask.request.files["image"].read()
				test_image = Image.open(io.BytesIO(test_image))
				test_image = prepare_image(test_image,
					(settings.IMAGE_WIDTH, settings.IMAGE_HEIGHT))

				# ensure our NumPy array is C-contiguous as well,
				# otherwise we won't be able to serialize it
				test_image = test_image.copy(order="C")
				test_image = helpers.base64_encode_image(test_image)
				print(test_image[:20]) # check format
			else:
				print('request.json.get')
				test_image = request.json.get('image')

				test_image = test_image[test_image.find('base64,')+7:]
				print (test_image[:20])
				fh = open("out.jpg", "wb")
				fh.write(test_image.decode('base64'))
				fh.close()
                
				test_file = 'out.jpg'
				test_image = Image.open(test_file)
				test_image = prepare_image(test_image,
					(settings.IMAGE_WIDTH, settings.IMAGE_HEIGHT))

				# ensure our NumPy array is C-contiguous as well,
				# otherwise we won't be able to serialize it
				test_image = test_image.copy(order="C")
				test_image = helpers.base64_encode_image(test_image)
				print(test_image[:20]) # check format

    
				# generate an ID for the classification then add the
			# classification ID + image to the queue
			k = str(uuid.uuid4())
			d = {"id": k, "image": test_image}
			redis_db.rpush(settings.IMAGE_QUEUE, json.dumps(d))

			# keep looping until our model server returns the output
			# predictions
			while True:
				# attempt to grab the output predictions
				output = redis_db.get(k)

				# check to see if our model has classified the input
				# image
				if output is not None:
					# add the output predictions to our data
					# dictionary so we can return it to the client
					output = output.decode("utf-8")
					data["predictions"] = json.loads(output)

					# delete the result from the database and break
					# from the polling loop
					redis_db.delete(k)
					break

				# sleep for a small amount to give the model a chance
				# to classify the input image
				time.sleep(settings.CLIENT_SLEEP)

			# indicate that the request was a success
			data["success"] = True
		else:
			print('failed to get image')

	# return the data dictionary as a JSON response
	return flask.jsonify(data)

# for debugging purposes, it's helpful to start the Flask testing
# server (don't use this for production
if __name__ == "__main__":
	print("* Starting web service...")
	app.run(ssl_context='adhoc', host='0.0.0.0', port=8443)
