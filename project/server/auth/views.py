# project/server/auth/views.py


from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, UserPost, Bill, Model

import datetime,decimal

auth_blueprint = Blueprint('auth', __name__)

def process_post_data():
    post_data_json = request.get_json()
    # Check if post_data_json main arguments are nested in the body
    return post_data_json.get('body') if 'body' in post_data_json else post_data_json

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = process_post_data()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class ModelLoaderAPI(MethodView):
    """
    Load Models for Dropdown
    """
    def get(self):
        try:
            models = Model.query.all()
            responseObject={'models':{}}
            for model in models:
                responseObject['models'][model.model_name]=model.allocation_array
            return make_response(jsonify(responseObject)), 200
        except Exception as e:
             responseObject = {
                 'status': 'fail',
                 'message': str(e)
             }
             return make_response(jsonify(responseObject)), 401



class BillDetailsLoaderAPI(MethodView):
    """
    Load Bill Details To View
    """
    def post(self):
        try:
            post_data = process_post_data()
            created_on = db.session.query(Bill).filter_by(bill_name=post_data.get('bill_name')).order_by(Bill.created_on.desc()).first().created_on
            bill_timestamp_id = db.session.query(Bill).filter_by(bill_name=post_data.get('bill_name')).order_by(Bill.bill_timestamp_id.desc()).first().bill_timestamp_id
            #bills = Bill.query.filter_by(bill_name=post_data.get('bill_name')).all()
            bills = Bill.query.filter_by(bill_name=post_data.get('bill_name')).filter_by(bill_timestamp_id=bill_timestamp_id).all()
            lineItems = []
            for line in bills:
                lineItems.append({'bill_name' : line.bill_name, 'bill_date' : line.bill_date, 'bill_amount' : float(line.bill_amount), 'line_name' : line.line_name, 'line_amount' : float(line.line_amount), 'line_number' : line.line_number, 'line_notes' : line.line_notes,'bill_timestamp_id': line.bill_timestamp_id})
            return make_response(jsonify({'lineItems': lineItems})), 200
        except Exception as e:
             responseObject = {
                 'status': 'fail',
                 'message': str(e)
             }
             return make_response(jsonify(responseObject)), 401


class BillLoaderAPI(MethodView):
    """
    Load Bill To View
    """
    def post(self):
        try:
            post_data = process_post_data()
            bills = Bill.query.filter_by(bill_name=post_data.get('bill_name')).all()
            total = 0.0
            entity_totals = [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0]
            for line in bills:
                print(line.allocation_array)
                for i,entity_mass in enumerate(line.allocation_array):
                    if entity_mass:
                        entity_totals[i]+=float(entity_mass)*float(line.line_amount)
                total+=float(line.line_amount)
                print("total: " + str(total))
                print("entity_totals: " + str(entity_totals))
            return make_response(jsonify({'total':total, 'entity_totals':entity_totals})), 200
        except Exception as e:
             responseObject = {
                 'status': 'fail',
                 'message': str(e)
             }
             return make_response(jsonify(responseObject)), 401


class BillNameLoaderAPI(MethodView):
    """
    Load Bill Names To View
    """
    def get(self):
        try:
            bills = Bill.query.distinct(Bill.bill_name)
            bill_names = []
            for bill in bills:
                bill_names.append(bill.bill_name)
            return make_response(jsonify({'bill_names': bill_names})), 200
        except Exception as e:
             responseObject = {
                 'status': 'fail',
                 'message': str(e)
             }
             return make_response(jsonify(responseObject)), 401

# Class to handle loading of blog feeds
class FeedAPI(MethodView):
    """
    User Feed Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                # Only return a reply if the user is a valid user.
                if user.id is not None:
                    user_posts = []
                    posts= user.posts
                    for x in posts:
                        user_post ={}
                        user_post['title']=x.title
                        user_post['body']=x.body
                        user_post['image']=x.image
                        user_post['link']=x.link
                        user_posts.append(user_post)
                    responseObject = {
                        'status': 'success',
                        'data': {
                            'user_id': user.id,
                            'email': user.email,
                            'admin': user.admin,
                            'registered_on': user.registered_on,
                            'posts': user_posts
                        }
                    }
                    return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class BillAPI(MethodView):
    """
    Post a Bill
    """

    def post(self):
        # get the post data
        post_data = process_post_data()
        # check if user already exists
	bill_name = "Test1"
        try:
            bill_name = post_data.get('bill_name')
            bill_date = post_data.get('bill_date')
            bill_timestamp_id = post_data.get('bill_timestamp_id')
            bill_amount = post_data.get('bill_amount')
            line_number = post_data.get('line_number')
            line_name = post_data.get('line_name')
            line_notes = post_data.get('line_notes')
            line_amount = post_data.get('line_amount')
            allocation_array = post_data.get('allocation_array')
            sent_to_ledger_flag = False
            bill = Bill(
                bill_name = bill_name,
                bill_date = bill_date,
                bill_timestamp_id = bill_timestamp_id,
                bill_amount = bill_amount,
                line_number=line_number,
                line_name=line_name,
                line_notes = line_notes,
                line_amount = line_amount,
                allocation_array = allocation_array,
                sent_to_ledger_flag=False                
            )
            # insert the user
            db.session.add(bill)
            db.session.commit()
            # generate the auth token
            responseObject = {
                'status': 'success',
                'message': 'Successfully added new Bill.' + str(bill_name),
            }
            return make_response(jsonify(responseObject)), 201
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Unexpected error ' + str(e) + '. Please try again.'
            }
            return make_response(jsonify(responseObject)), 401



class ModelAPI(MethodView):
    """
    Save a Model for future billing
    """

    def post(self):
        # get the post data
        post_data = process_post_data()
       
        try:
            model = Model(
                model_name = post_data.get('model_name'),
                allocation_array = post_data.get('allocation_array')
            )
            # insert the user   
            db.session.add(model)
            db.session.commit()
            # generate the auth token
            responseObject = {
                'status': 'success',
                'message': 'Successfully added new Model.' + str(model),
            }
            return make_response(jsonify(responseObject)), 201
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Unexpected error ' + str(e) + '. Please try again.'
            }
            return make_response(jsonify(responseObject)), 401



class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = process_post_data()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

# Class to handle loading of blog feeds
class FeedAPI(MethodView):
    """
    User Feed Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                # Only return a reply if the user is a valid user.
                if user.id is not None:
                    user_posts = []
                    posts= user.posts
                    for x in posts:
                        user_post ={}
                        user_post['title']=x.title
                        user_post['body']=x.body
                        user_post['image']=x.image
                        user_post['link']=x.link
                        user_posts.append(user_post)
                    responseObject = {
                        'status': 'success',
                        'data': {
                            'user_id': user.id,
                            'email': user.email,
                            'admin': user.admin,
                            'registered_on': user.registered_on,
                            'posts': user_posts
                        }
                    }
                    return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


# Class to handle posting of a blog feed
class PostAPI(MethodView):
    """
    User Post Resource
    """
    def post(self):
        # post the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                # Only return a reply if the user is a valid user.
                if user.id is not None:
                    # get the post data
                    print(request.get_json())
                    post_data = process_post_data()
                    if post_data:
                        p = UserPost(title='Bye Bye', body = """ Bomb bomb bomb roseannneeeeeee...... Roxaneee, you dont have to put on the alt-right! Those days are ova you dont have to say any race is wrong or right. """, image = "https://si.wsj.net/public/resources/images/S1-AK715_MUSKME_E_20180523183001.jpg", user_id=1)
                        p = UserPost(title=post_data.get('title'), body=post_data.get('body'), image=post_data.get('image'),link=post_data.get('link') ,user_id=post_data.get('user_id') )
                        db.session.add(p)
                        db.session.commit()
                        responseObject = {
                            'status': 'success',
                            'data': {
                                'user_id': user.id,
                                'email': user.email,
                                'admin': user.admin,
                                'registered_on': user.registered_on,
                            }
                        }
                        return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403

# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
feed_view = FeedAPI.as_view('feed_api')
post_view = PostAPI.as_view('post_api')
bill_view = BillAPI.as_view('bill_api')
model_view = ModelAPI.as_view('model_api')
bill_loader_view = BillLoaderAPI.as_view('bill_loader_api')
bill_details_loader_view = BillDetailsLoaderAPI.as_view('bill_details_loader_api')
bill_name_loader_view = BillNameLoaderAPI.as_view('bill_name_loader_api')
model_loader_view = ModelLoaderAPI.as_view('model_loader_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/feed',
    view_func=feed_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/post',
    view_func=post_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/bills',
    view_func=bill_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/models',
    view_func=model_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/bills/names/load',
    view_func=bill_name_loader_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/bills/details',
    view_func=bill_details_loader_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/bills/load',
    view_func=bill_loader_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/models/load',
    view_func=model_loader_view,
    methods=['GET']
)
