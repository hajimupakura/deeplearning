from keras.preprocessing.image import img_to_array
from keras.applications import imagenet_utils
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
from flask_cors import CORS, cross_origin
from flask import jsonify, request, abort
import requests
import logging #the module we`re using for printing

from flask_limiter import Limiter #limiting the number of requests a user can send
from flask_limiter.util import get_remote_address
from ratelimit import limits

import tensorflow as tf
import os
import random
import pickle
import numpy as np
import matplotlib.pyplot
from matplotlib.pyplot import imshow
import keras
from keras.preprocessing import image
from keras.applications.imagenet_utils import decode_predictions, preprocess_input
from keras.models import Model
from sklearn.decomposition import PCA
from scipy.spatial import distance
from tqdm import tqdm

#libraries for defining user access
from functools import wraps
from flask import url_for, request, redirect, session
# from user import User

# import Flask related packages for user management and authentication
from flask import Flask, render_template, current_app
from flask import abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, auth_token_required, utils, current_user

from flask_security.decorators import http_auth_required, roles_required, roles_accepted
from flask import jsonify, request, abort

from functools import wraps
# from flask_login import login_user, logout_user, current_user # flask_logins implementations of login_user, logout_user, current_user seem more seamless

from flask_cors import CORS, cross_origin
# from flask_login import LoginManager
from itsdangerous import URLSafeTimedSerializer
import datetime

from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy.orm import relationship
from sqlalchemy import exc
# initialize our Flask application and Redis server
app = flask.Flask(__name__)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["2 per minute", "1 per second"], #limiting the number of requests that can be sent
    
)
limiter.init_app(app),
ratelimit_storage_url = 'redis://rate-limiting.amazonaws.com:6379'
db = redis.StrictRedis(host=settings.REDIS_HOST,
    port=settings.REDIS_PORT, db=settings.REDIS_DB)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_PASSWORD_SALT'] = 'super-secret'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cbir.sqlite'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://mudzi:z32EM2%GhK%jc3@cbir.cd81orwyjedt.us-east-1.rds.amazonaws.com/cbir'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://tariro:yBNI#$nH%S]]@mysql8test.cd81orwyjedt.us-east-1.rds.amazonaws.com/mysql8test'

app.config['SECURITY_TOKEN_AUTHENTICATION_KEY'] = 'token'
login_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

cors = CORS(app, resources={r"/*": {"origins": "*"}})

db = SQLAlchemy(app)

auth = HTTPBasicAuth()


#DEFINING USER ACCESS LEVELS BY USING DECORATORS
# def requires_access_level(access_level):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if not session.get('email'):
#                 return redirect(url_for('users.login')
#                                 user = User.find_by_email(session['email'])
#                                 elif not user.allowed(access_level):
#                                 return redirect(url_for('users.profile', message="You do not have access to that page. Sorry!"))
#                                 return f(*args, **kwargs)
#                                 return decorated_function
#                                 return decorator
                                
# UPDATE user SET is_admin = TRUE WHERE api_key='e3c88024-0ce6-47f9-97f4-f7b15bc69a1c';
# ALTER TABLE user ADD COLUMN rate_limit INT DEFAULT 10 AFTER active;

# The actual decorator function
def require_admin(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        print(g.user)
        if g.user.is_admin!=True:            
            return jsonify({ 'message': "User with api key: " + g.user.api_key + " does not have the priviledges to access this resource." }), 403
        return view_function(*args, **kwargs)
    return decorated_function


class Application(db.Model):
#     id = db.Column(db.Integer(), primary_key=True)
    app_id = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.String(255))
    status = db.Column(db.String(80))
    owner = db.Column(db.String(80))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=db.func.utc_timestamp())
    active = db.Column(db.Boolean())
    version = db.Column(db.String(80))
    lock = db.Column(db.Boolean())
    
    def to_dict(self):
          return {'app_id': str(self.app_id), 'name': self.name, 'description': self.description, 'status': self.status, 'owner': self.owner, 'created': str(self.created), 'updated': str(self.updated), 'active': str(self.active)}

    def __str__(self):
        return json.dumps(self.to_dict())
    
roles_users = db.Table('roles_users',
        db.Column('user_id', db.String(255), db.ForeignKey('user.api_key')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

# roles_users = db.Table('roles_users',
#         db.Column('user_id', db.Integer()),
#         db.Column('role_id', db.Integer()))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    
class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(255), primary_key=True)
    secret_key = db.Column(db.String(255))
    owner = db.Column(db.String(255))
    description = db.Column(db.String(255))
    app_id = db.Column(db.String(255))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=db.func.utc_timestamp())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    active = db.Column(db.Boolean())
    rate_limit = db.Column(db.Integer())
    is_admin = db.Column(db.Boolean, nullable=False)

    def to_dict(self):
#         return {'api_key': str(self.api_key), 'secret_key': str(self.secret_key)}
          return {'api_key': str(self.api_key), 'secret_key': self.secret_key, 'owner': self.owner, 'description': self.description, 'app-id': self.app_id, 'created': str(self.created), 'updated': str(self.updated), 'roles': str(self.roles), 'active': str(self.active), 'is_admin': str(self.is_admin)}

    def __str__(self):
        return json.dumps(self.to_dict())
#         return "api_key: " + str(self.api_key) + ", api_key: " + self.api_key + ", is_authenticated: " +  str(self.is_authenticated)
                
    def hash_password(self, secret_key):
        self.secret_key = pwd_context.encrypt(secret_key)

    def verify_keys(self, secret_key):
        return secret_key == self.secret_key
# Define models
# apps_users = db.Table('apps_users',
#         db.Column('user_id', db.Integer(), db.ForeignKey('user.api_key')),
#         db.Column('app_id', db.Integer(), db.ForeignKey('application.app_id')))    
    
class Image(db.Model):
#     id = db.Column(db.Integer(), primary_key=True)
    image_id = db.Column(db.String(80), primary_key=True)
    insertion_id = db.Column(db.String(80))
    image_url = db.Column(db.String(80), unique=True)
    parent_id = db.Column(db.String(255))
    app_id = db.Column(db.String(80))
    category = db.Column(db.String(80))
    price = db.Column(db.String(80))
    brand = db.Column(db.String(80))
    title = db.Column(db.String(80))
    status_code = db.Column(db.Integer())
    status_message = db.Column(db.String(2048))
    features = db.Column(db.String(2048))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=db.func.utc_timestamp())
    
    def to_dict(self):
#         return {'api_key': str(self.api_key), 'secret_key': str(self.secret_key)}
        if self.features==None:
            self.features=""
          
        return {'image_id': str(self.image_id), 'insertion_id': str(self.insertion_id), 'image_url': str(self.image_url), 'parent_id': self.parent_id, 'created': self.created, 'status': { 'code': self.status_code, 'message': self.status_message}, 'created': str(self.created), 'updated': str(self.updated), 'features': str(len(self.features))}

    def __str__(self):
        return json.dumps(self.to_dict())

class Search_Result(db.Model):
#     id = db.Column(db.Integer(), primary_key=True)
    search_id = db.Column(db.String(80), primary_key=True)
    app_id = db.Column(db.String(80))
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    response_time = db.Column(db.Integer())
    full_results = db.Column(db.String(80))
    
    
db.create_all()
# apps_users.insert().values([{"user_id": 1}, {"app_id": 1}])

@app.before_first_request
def create_user():
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info(' ')
    db.create_all()

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
max_age = 600


@auth.verify_password
def verify_keys(api_key, secret_key):
    user = User.query.filter_by(api_key = api_key).first()
    if not user or not user.verify_keys(secret_key):
        return False

    current_user = user
    g.user = user
    return True

# Create a new set of user keys
@app.route('/api/keys', methods = ['POST'])
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def new_key():
    owner = request.json.get('owner')
    app_id = request.json.get('app-id')
    description =  request.json.get('description')
#     print(owner)
    
    if owner is None or app_id is None:
        abort(400, "Missing user details. You must provide the app-id and app owner") # missing arguments
        
    if Application.query.filter_by(app_id = app_id).first() is None:
#         abort(400, "Application with app_id: " + app_id + " does not exist") # existing user
        return jsonify({ 'message': "Application with app_id: " + app_id + " does not exist" }), 400
        
    api_key = str(uuid.uuid4()) #generate_key()
    secret_key = str(uuid.uuid4()) #generate_key()
#     print(api_key)
#     print(secret_key)
    
    
    if User.query.filter_by(api_key = api_key).first() is not None:
        abort(400, "User key already exists") # existing user
    user = User(api_key = api_key, secret_key = secret_key, owner = owner, description = description, app_id = app_id, active = True)
    
#     user.hash_password(secret_key)
    db.session.add(user)
    result = db.session.commit()
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info("result: ") 
    logging.info(user)
    return jsonify(user.to_dict()), 201

# Enabling application title ad description to be updated
# TO DO: Admin accounts should be given access
@app.route('/api/keys', methods = ['GET'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def update_keys():
#     owner = request.json.get('owner')
    app_id = request.args.get('app-id')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info(app_id)
    logging.info(g.user) 
    if g.user.app_id != app_id:
        abort(403, "You are not authorised to access this item") # missing arguments
        
    if app_id is None:
        abort(400, "Missing user details") # missing arguments
        
#     if Application.query.filter_by(owner = owner).first() is  None:
#         abort(400, "No applications found")
    results = User.query.filter_by(app_id = app_id).all()
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (len(results)) 
    logging.info (results)
    keys =[]
    for result in results:
        keys.append(result.to_dict())
#     db.session.commit()
    return jsonify(keys), 200

# Delete 
# TO DO: Only Admin accounts should be given access
@app.route('/api/keys/<api_key>', methods = ['DELETE'])
@auth.login_required
def delete_key(api_key):
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (api_key)
#     print (g.user)
#     if g.user.app_id != app_id:
#         abort(403, "You are not authorised to access this item") # missing arguments
        
    if api_key is None:
        abort(400, "Missing user details") # missing arguments
        
#     if Application.query.filter_by(owner = owner).first() is  None:
#         abort(400, "No applications found")
    results = User.query.filter_by(api_key=api_key).delete()
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (results)
    
    db.session.commit()

    return jsonify(''), 200

# to update api_keys details i.e title and description 
# TO DO: Only Admin accounts should be given access
@app.route('/api/keys/<api_key>', methods = ['POST'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def update_key(api_key):
    owner = request.json.get('owner')
    description = request.json.get('description')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (owner)
    #     print (g.user)
#     if g.user.app_id != app_id:
#         abort(403, "You are not authorised to access this item") # missing arguments
        
    if api_key is None:
        abort(400, "Missing user details") # missing arguments
        
#     if Application.query.filter_by(owner = owner).first() is  None:
#         abort(400, "No applications found")
    result = User.query.filter_by(api_key=api_key).update({"owner":owner, "description":description})
    db.session.commit()

    print (result)

    #return jsonify(''), 200
    if result is  None:
            abort(400, "No applications found")
        
    if g.user.api_key != api_key:
        abort(403, "You are not authorised to access this item") # missing arguments
        
    if api_key is None:
        abort(400, "Missing Application key") # missing arguments
        
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info ("let's see what our result is")
    logging.info(result)
    

    logging.info("the result was printed above")
    if(result==1):
        return jsonify({"Success": "Application keys updated"}), 200 
    else:
        return jsonify({"Error": "Failed to update"}), 200

# Create a new application
@app.route('/api/applications', methods = ['POST'])
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def new_application():
    owner = request.json.get('owner')
    name = request.json.get('name')
    description = request.json.get('description')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (owner)
    
    if owner is None:
        abort(400, "Missing user details") # missing arguments
        
    app_id = str(uuid.uuid4())
    if Application.query.filter_by(app_id = app_id).first() is not None:
        abort(400, "app_id already exists") # existing user
    
    application = Application(app_id = app_id, name = name, description = description, owner = owner, status = 'created', active = True)
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (application)
    db.session.add(application)
    db.session.commit()
    return jsonify(application.to_dict()), 201

# Get list of applications belonging to a user
# The request is in the format https://34.201.204.155:8443/api/applications?owner=test-f7a5-439e-bc84-60f742e09061 
# TO DO: Admin accounts should be given access
@app.route('/api/applications', methods = ['GET'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def retrieve_applications():
#     owner = request.json.get('owner')
    owner = request.args.get('owner')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (owner)
    logging.info (g.user)
    if g.user.owner != owner:
        abort(403, "You are not authorised to access this item") # missing arguments
        
    if owner is None:
        abort(400, "Missing user details") # missing arguments
        
#     if Application.query.filter_by(owner = owner).first() is  None:
#         abort(400, "No applications found")
    results = Application.query.filter_by(owner = owner).all()
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (len(results))
    logging.info (results)
    applications =[]
    for result in results:
        applications.append(result.to_dict())
#     db.session.commit()
    return jsonify(applications), 200

def rate_limit_from_config():
    return str(g.user.rate_limit) + " per minute"

# Retrieve application details
# TO DO: Admin accounts should be given access
@app.route('/api/applications/<app_id>', methods = ['GET'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
@require_admin
def retrieve_application(app_id):
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (app_id)
#     print (g.user)
    result = Application.query.filter_by(app_id=app_id).first()
    if result is  None:
            abort(400, "No applications found")
        
    if g.user.app_id != app_id:
        abort(403, "You are not authorised to access this item") # missing arguments
        
    if app_id is None:
        abort(400, "Missing app-id") # missing arguments

    logging.info (result)

    return jsonify(result.to_dict()), 200

# to update application details i.e title and description
# TO DO: Admin accounts should be given access
@app.route('/api/applications/<app_id>', methods = ['POST'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def update_application(app_id):
    name = request.json.get('name')
    description = request.json.get('description')
    print(description)
#     print (g.user)
    result = Application.query.filter_by(app_id=app_id).update({"name":name, "description":description})
    db.session.commit()
    if result is  None:
            abort(400, "No applications found")
        
    if g.user.app_id != app_id:
        abort(403, "You are not authorised to access this item") # missing arguments
        
    if app_id is None:
        abort(400, "Missing app-id") # missing arguments
         
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info ("let's see what our result is")
    logging.info (result)
    

    logging.info ("the result was prrinted above")
    if(result==1):
        return jsonify({"Success": "Application details updated"}), 200 
    else:
        return jsonify({"Error": "Failed to update"}), 200

    # Delete application
# TO DO: Admin accounts should be given access
@app.route('/api/applications/<app_id>', methods = ['DELETE'])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def delete_application(app_id):
#     owner = request.json.get('owner')
#     app_id = request.args.get('app-id')
    print(app_id)
#     print (g.user)
#     if g.user.app_id != app_id:
#         abort(403, "You are not authorised to access this item") # missing arguments
        
    if app_id is None:
        abort(400, "Missing app-id") # missing arguments
        
#     if Application.query.filter_by(owner = owner).first() is  None:
#         abort(400, "No applications found")
    results = Application.query.filter_by(app_id=app_id).delete()

    logging.info (results)
    db.session.commit()

    return jsonify(''), 200

# Create a new user
@app.route('/api/users', methods = ['POST'])
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (username)
    logging.info (password)
    
    if username is None or password is None:
        abort(400, "Missing user details") # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400, "User already exists") # existing user
    user = User(email = username, username = username)
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (user)
#     user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({ 'username': user.username }), 201
#     {'Location': url_for('get_user', id = user.id, _external = True)}

# Check if the user has the required role for this action
def check_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print(roles)
            print(g.user.roles)
            print(user_datastore.find_role('admin'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/resource')
@auth.login_required
@check_role('admin,editor')
# @roles_accepted('admin', 'editor')
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.owner })


def prepare_image(image, target):
	# if the image mode is not RGB, convert it
	if image.mode != "RGB":
		image = image.convert("RGB")

	# resize the input image and preprocess it
	image = image.resize(target)
	image = img_to_array(image)
	image = np.expand_dims(image, axis=0)
	image = imagenet_utils.preprocess_input(image)

	# return the processed image
	return image

# get_image will return a handle to the image itself, and a numpy array of its pixels to input the network
def get_image(path):
    img = image.load_img(path, target_size=model.input_shape[1:3])
    x = image.img_to_array(img)
    x = np.expand_dims(x, axis=0)
    x = preprocess_input(x)
    return img, x

#     We will load a previously-trained neural network, that of Resnet, which comes with Keras.
model = None
feat_extractor = None
graph = None

def load_model():
    # load the pre-trained Keras model (here we are using a model
    # pre-trained on ImageNet and provided by Keras, but you can
    # substitute in your own networks just as easily)
    global model
    global feat_extractor
    # https://github.com/keras-team/keras/issues/2397
    global graph
    model = keras.applications.resnet50.ResNet50(weights='imagenet', include_top=True)
    graph = tf.get_default_graph()
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info ("* Pretrained model loaded")
        #     Now we will remove the top classification layer from our network, leaving the last fully-connected layer,
    feat_extractor = Model(inputs=model.input, outputs=model.get_layer("flatten_1").output)
    


def run_indexing(app_id):
    data = []
    images_path = '../data/' + app_id
#     images_path = '../dataturks'
    # images_path = '/mnt/data/datasets/chnmcu256train'

    max_num_images = 30

    images = [os.path.join(dp, f) for dp, dn, filenames in os.walk(images_path) for f in filenames if os.path.splitext(f)[1].lower() in ['.jpg','.png','.jpeg']]
    if max_num_images < len(images):
        images = [images[i] for i in sorted(random.sample(xrange(len(images)), max_num_images))]
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
        logging.info ("keeping %d images to analyze" % len(images))
    
    # The next part will take the longest. We iterate through and extract the features from all the images in our images array, placing them into an array called features.
    global graph
    with graph.as_default():
        features = []
        for image_path in tqdm(images):
            img, x = get_image(image_path);
            feat = feat_extractor.predict(x)[0]
            logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
            logging.info (feat)
            features.append(feat)

        pca_features = features
#         features = np.array(features)
#         pca = PCA(n_components=300)
#         pca.fit(features)
#         pca_features = pca.transform(features)

    # define the name of the directory to be created
#         path = "../models/" + app_id

#         try:  
#             os.mkdir(path)
#         except OSError:  
#             print ("Creation of the directory %s failed" % path)
#         else:  
#             print ("Successfully created the directory %s " % path)

        pickle.dump([images, pca_features], open('../models/' + app_id + '.p', 'wb'))

    
#         data["success"] = True
#         data["result"] = 'Indexing complete'

    data = {"success": True, "result": 'Indexing complete'}

    return data

# @app.route('/api/resource')
# @auth.login_required
# @check_role('admin,editor')
# # @roles_accepted('admin', 'editor')
# def get_resource():
#     return jsonify({ 'data': 'Hello, %s!' % g.user.owner })

@app.route("/api/verify-keys", methods=["POST"])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
@cross_origin()
def verify_keys():
	return jsonify({"status": {"code": 10000,"description": "Ok"},"message" : "The supplied keys are valid"})

@app.route("/api/status", methods=["GET"])
@cross_origin() 
@auth.login_required
def homepage():
	return jsonify({"status": {"code": 10000,"description": "Ok"},"message" : "Our InteliKit API is now  running"})

# Add new images to the index. 
# This endpoint is meant to receive a json request with details of the images to be add. Does not receive image files but urls to the images which must be publicly accessible.
@app.route("/api/inputs", methods=["POST"])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
@cross_origin() 
def index():
#     Get the post data
    data = request.json.get('data')

#     Get the app id for the logged in user key pair
    app_id = g.user.app_id
    
    # define the name of the directory to be created
    path = "../data/" + app_id

    try:  
        os.mkdir(path)
    except OSError:
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.ERROR)
        logging.error ("Creation of the directory %s failed" % path)
        
    else:
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
        logging.info ("Successfully created the directory %s " % path)
        
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info (type(data))
    logging.info (len(data))

    images = json.dumps(data)
    images = json.loads(images)
    insertion_id = str(uuid.uuid4())
    response = []
    for image in images:
        parent_id = image['parent_id']
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
        logging.info(parent_id)
        image_url = image['image_url']
        logging.info(image_url)

        logging.info('Beginning file download with requests')
        
        if image_url != False:
            image_id = str(uuid.uuid4())
#             if Image.query.filter_by(app_id = app_id).first() is not None:
#                 abort(400, "app_id already exists") # existing user

            try:
                image = Image(image_id = image_id, insertion_id = insertion_id, image_url = image_url, parent_id = parent_id, status_code = 201, status_message = 'Pending download.', app_id = app_id)
                print(image)
                db.session.add(image)
                db.session.commit()


                response.append(image.to_dict())
            except exc.IntegrityError as e:
                print (e.message)
                db.session().rollback()
                response.append({"message": e.message})
            
#         return jsonify(image.to_dict()), 201
    return jsonify(response), 201
#                 filename = image_url[image_url.rfind("/")+1:]
#                 print (filename)
#                 r = requests.get(image_url)

#                 with open(path + '/' + filename, 'wb') as f:  
#                     f.write(r.content)

#                 # Retrieve HTTP meta-data
#                 print(r.status_code)  
#                 print(r.headers['content-type'])  
#                 print(r.encoding)  

#         for image_url in product["images"]:
#             print (image_url)
#             print('Beginning file download with requests')

#             if image_url != False:
#                 filename = image_url[image_url.rfind("/")+1:]
#                 print (filename)
#                 r = requests.get(image_url)

#                 with open(path + '/' + filename, 'wb') as f:  
#                     f.write(r.content)

#                 # Retrieve HTTP meta-data
#                 print(r.status_code)  
#                 print(r.headers['content-type'])  
#                 print(r.encoding)  
#     json_data = request.json
#     #     print (json_data)
#     products = json_data['data']
#     print products
    data = {"success": False}
#     data = run_indexing(app_id)
    # return the data dictionary as a JSON response
    return flask.jsonify(data)

@app.route("/api/oldindex", methods=["POST"])
@auth.login_required
@limiter.limit(rate_limit_from_config, key_func = lambda : g.user.api_key)
@cross_origin() 
def oldindex():
#     Get the post data
    data = request.json.get('data')

#     Get the app id for the logged in user key pair
    app_id = g.user.app_id
    
    # define the name of the directory to be created
    path = "../data/" + app_id

    try:  
        os.mkdir(path)
    except OSError:  
        print ("Creation of the directory %s failed" % path)
    else:  
        print ("Successfully created the directory %s " % path)
        
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info(type(data))
    logging.info(len(data))

    products = json.dumps(data)
    products = json.loads(products)
    for product in products:
        print (product["id"])
        for image_url in product["images"]:
            logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
            logging.info(image_url)
            logging.info('Beginning file download with requests')
            

            if image_url != False:
                filename = image_url[image_url.rfind("/")+1:]
                logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
                logging.info(filename)
                r = requests.get(image_url)

                with open(path + '/' + filename, 'wb') as f:  
                    f.write(r.content)

                # Retrieve HTTP meta-data
                logging.info(r.status_code)
                logging.info(r.headers['content-type'])
                logging.info(r.encoding)
                  
#     json_data = request.json
#     #     print (json_data)
#     products = json_data['data']
#     print products
    data = {"success": False}
    data = run_indexing(app_id)
    # return the data dictionary as a JSON response
    return flask.jsonify(data)
    
@app.route("/predict", methods=["POST"])
@cross_origin() 
def predict():
    # initialize the data dictionary that will be returned from the
    # view
    app_id = request.args.get('app-id')
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info('app-id = ' + app_id)
    data = {"success": False}

    # ensure an image was properly uploaded to our endpoint
    if flask.request.method == "POST":
        if flask.request.files.get("image"):
            # read the image in PIL format and prepare it for
            # classification
            image = flask.request.files["image"].read()
            image = Image.open(io.BytesIO(image))
            image = prepare_image(image,
                (settings.IMAGE_WIDTH, settings.IMAGE_HEIGHT))

            # ensure our NumPy array is C-contiguous as well,
            # otherwise we won't be able to serialize it
            image = image.copy(order="C")

            # generate an ID for the classification then add the
            # classification ID + image to the queue
            k = app_id + '.'+str(uuid.uuid4())
            print (k)
            image = helpers.base64_encode_image(image)
            d = {"id": k, "image": image}
            db.rpush(settings.IMAGE_QUEUE, json.dumps(d))

            # keep looping until our model server returns the output
            # predictions
            while True:
                # attempt to grab the output predictions
                output = db.get(k)

                # check to see if our model has classified the input
                # image
                if output is not None:
                    # add the output predictions to our data
                    # dictionary so we can return it to the client
                    output = output.decode("utf-8")
                    data["predictions"] = json.loads(output)

                    # delete the result from the database and break
                    # from the polling loop
                    db.delete(k)
                    break

                # sleep for a small amount to give the model a chance
                # to classify the input image
                time.sleep(settings.CLIENT_SLEEP)

            # indicate that the request was a success
            data["success"] = True

    # return the data dictionary as a JSON response
    return flask.jsonify(data)

#limiting the number of requests a user will send
@app.route("/fast")
def fast():
    return "42"
# for debugging purposes, it's helpful to start the Flask testing
# server (don't use this for production
if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info('* Starting web service...')
    # 	app.run(host='0.0.0.0', port=8080)
#     load_model()
    app.run(ssl_context='adhoc', host='0.0.0.0', port=8443)
