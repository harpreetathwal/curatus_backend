# project/server/models.py


import jwt
import datetime

from project.server import app, db, bcrypt

class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship('UserPost', backref='user')

    def __init__(self, email, password, admin=False, **kwargs):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


class UserPost(db.Model):
    """ User Post Model for storing posts made by users """
    __tablename__ = "user_posts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), unique=False, nullable=False)
    body = db.Column(db.String(2000), nullable=True)
    link = db.Column(db.String(1000), nullable=True)
    image = db.Column(db.String(1000), nullable=True)
    created_on = db.Column(db.DateTime, nullable=False, index=True)
    visibility = db.Column(db.Boolean, nullable=False, default=True)
    delete_flag = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, title = "Empty Post Title", body="empty post body", link="", image="", visibility=True, delete_flag=False, user_id=None, **kwargs):
        self.user_id = user_id
        self.title = title
        self.body = body
        self.link = link
        self.image = image
        self.created_on = datetime.datetime.now()
        self.visibility = visibility
        self.delete_flag = delete_flag


class Bill(db.Model):
    """ Billing table for storing line item allocated bills """
    __tablename__ = "bills"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    bill_name = db.Column(db.String(250), unique=False, nullable=False)
    bill_timestamp_id = db.Column(db.String(250), unique=False, nullable=False)
    bill_date = db.Column(db.Date, nullable=False, index=True)
    bill_amount = db.Column(db.Numeric(15,2), unique=False, nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    line_name = db.Column(db.String(250), nullable=True)
    line_notes = db.Column(db.String(1000), nullable=True)
    line_amount = db.Column(db.Numeric(15,2), unique=False, nullable=False)
    allocation_array = db.Column(db.ARRAY(db.Float), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False, index=True)
    sent_to_ledger_flag = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, bill_name = "", bill_date = datetime.date.today(), bill_timestamp_id = str(datetime.date.today()), bill_amount = 0.0, line_number=0, line_name="", line_notes = "", line_amount = 0.0,  allocation_array = [0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1], sent_to_ledger_flag=False, **kwargs):
        self.bill_name = bill_name
        self.bill_timestamp_id = bill_timestamp_id
        self.bill_date = bill_date
        self.bill_amount = bill_amount
	self.line_number = line_number
	self.line_name = line_name
	self.line_notes = line_notes
	self.line_amount = line_amount
        self.created_on = datetime.datetime.now()
	self.allocation_array = allocation_array
        self.sent_to_ledger_flag = sent_to_ledger_flag


class Model(db.Model):
    """ Model table for storing models of cost allocation """
    __tablename__ = "models"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    model_name = db.Column(db.String(250), unique=False, nullable=False)
    allocation_array = db.Column(db.ARRAY(db.Float), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False, index=True)

    def __init__(self, model_name = "", allocation_array = [0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1], **kwargs):
        self.model_name = model_name
        self.allocation_array = allocation_array
        self.created_on = datetime.datetime.now()
