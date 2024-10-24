from flask import Blueprint, request, jsonify
from models import User
from utils import send_otp, generate_otp
import bcrypt
import datetime
import jwt
import os
import requests

auth_routes = Blueprint('auth', __name__)

# Secret key for encoding the JWT
SECRET_KEY = 'eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTcyMDc2Njk0OSwiaWF0IjoxNzIwNzY2OTQ5fQ.ELGetoyLjwBycyBKMBuuQ_Wig5qOK2LGwzJozoVY-4c'


# IPQS API Key
API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'

def validate_email(email):
    url = f'https://ipqualityscore.com/api/json/email/{API_KEY}/{email}'
    response = requests.get(url)
    if response.status_code == 200:
        result = response.json()
        return result.get('valid', False)
    return False

@auth_routes.route('/register', methods=['POST'])
def register():
    data = request.json

    email = data.get('email')
    password = data.get('password')

    # Validate email
    if not validate_email(email):
        return jsonify({'message': 'Invalid email'}), 400

    # Check if user already exists
    if User.objects(email=email):
        return jsonify({'message': 'User already exists'}), 400

    # Generate OTP and save it in the database with an expiry time
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
    user = User(email=email, password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), otp=otp, otp_expiry=otp_expiry)
    user.save()

    # Send OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'OTP sent successfully'}), 200

@auth_routes.route('/loginotp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp_entered = data.get('otp')

    # Find user by email and OTP
    user = User.objects(email=email, otp=otp_entered).first()
    if not user:
        return jsonify({'message': 'Invalid OTP'}), 400

    # Check if OTP is expired
    if datetime.datetime.now() > user.otp_expiry:
        return jsonify({'message': 'OTP has expired'}), 400

    # Set verification status to True
    user.verification = True
    user.save()

    return jsonify({'message': 'OTP verified successfully'}), 200

@auth_routes.route('/resend_otp', methods=['POST'])
def resend_otp():
    data = request.json
    email = data.get('email')

    # Find the user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate a new OTP
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

    # Update the user's OTP and OTP expiry in the database
    user.otp = otp
    user.otp_expiry = otp_expiry
    user.save()

    # Send the new OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'New OTP sent successfully'}), 200

@auth_routes.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 404

    # Check if user is verified
    if not user.verification:
        return jsonify({'message': 'User not verified'}), 400

    # Check if password is correct
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Incorrect password'}), 400

    # Generate JWT token
    token = jwt.encode(
    {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
    SECRET_KEY,
    algorithm='HS256'
)


    # return jsonify({'message': 'Login successful', 'token': token}), 200
    # Include subscription status in the response
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'subscription_status': user.subscription_status
    }), 200


@auth_routes.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate a new OTP
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

    # Update the user's OTP and OTP expiry in the database
    user.otp = otp
    user.otp_expiry = otp_expiry
    user.save()

    # Send the OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'OTP sent successfully'}), 200



@auth_routes.route('/resetpassword', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    # Debugging: Print incoming data
    print(f"Email: {email}, New Password: {new_password}")

    # Check if email and new_password are provided
    if not email or not new_password:
        return jsonify({'message': 'Email and new password are required'}), 400

    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    try:
        # Update the user's password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = hashed_password
        user.save()
        
        # Debugging: Print success
        print(f"Password for user {user.email} reset successfully")
    except Exception as e:
        print(f"Error resetting password: {e}")
        return jsonify({'message': 'Failed to reset password. Please try again.'}), 500

    return jsonify({'message': 'Password reset successfully'}), 200



@auth_routes.route('/razorpay_webhook', methods=['POST'])
def razorpay_webhook():
    data = request.json
    event = data.get('event')
    payload = data.get('payload', {})
    
    if event == "subscription.activated":
        subscription_id = payload['subscription']['entity']['id']
        user = User.objects(subscription_id=subscription_id).first()

        '''this logic are monthly plan only'''
        if user:
            user.subscription_status = "active"
            user.subscription_start = datetime.datetime.now()
            user.subscription_end = datetime.datetime.now() + datetime.timedelta(days=30)  #  for a 1-month subscription
            user.save()

        '''this logic for weekly, monthly and yearly plans'''
        '''       
          # Determine subscription duration based on (plan_id)
        if user:
            if plan_id == 'weekly_plan_id':  
                user.subscription_status = "active"
                user.subscription_start = datetime.datetime.now()
                user.subscription_end = datetime.datetime.now() + datetime.timedelta(weeks=1)  # 1-week plan
            elif plan_id == 'monthly_plan_id':  
                user.subscription_status = "active"
                user.subscription_start = datetime.datetime.now()
                user.subscription_end = datetime.datetime.now() + datetime.timedelta(days=30)  # 1-month plan
            elif plan_id == 'yearly_plan_id':  
                user.subscription_status = "active"
                user.subscription_start = datetime.datetime.now()
                user.subscription_end = datetime.datetime.now() + datetime.timedelta(days=365)  # 1-year plan
            user.save()
            '''
    
    elif event == "subscription.completed" or event == "subscription.halted":
        subscription_id = payload['subscription']['entity']['id']
        user = User.objects(subscription_id=subscription_id).first()
        if user:
            user.subscription_status = "inactive"
            user.subscription_end = datetime.datetime.now()
            user.save()
    
    return jsonify({'message': 'Webhook received'}), 200


def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = User.objects(email=data['email']).first()
        except Exception as e:
            print(f"Token verification failed: {e}")
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorator



def subscription_required(f):
    def decorator(current_user, *args, **kwargs):
        if current_user.subscription_status != "active":
            return jsonify({'message': 'Subscription required to access this feature'}), 403
        return f(current_user, *args, **kwargs)
    return decorator


@auth_routes.route('/protected', methods=['GET'])
@token_required
def protected(current_user):

    # Assuming subscription_status is part of the User model
    user = current_user.email
    subscription_status = current_user.subscription_status or 'Unknown'
    subscription_start = current_user.subscription_start
    subscription_end = current_user.subscription_end

    return jsonify({'message': 'This is a protected route', 'user': user, 'subscription_status': subscription_status, "subscription_start":subscription_start, "subscription_end":subscription_end})
