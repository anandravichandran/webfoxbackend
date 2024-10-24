import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from io import BytesIO
import requests



# Function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp(email, otp):
    sender_email = 'info@thinkinfoexpertsolutions.com'  
    sender_password = 'ruiz swhi hhfc cfoi'
    # sender_password = 'ygeo xcrk xmdc ldwb'

    #  the email content
    subject = f'Your OTP Code for WEBFOXSHIELD Verification'
    body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                width: 100%;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: #eeedf1;
            }}
            .email-header {{
                text-align: center;
                margin-bottom: 20px;
                background-color:#0c0221 ;
            }}
            .email-header img {{
                max-width: 150px;
                height: auto;
            }}
            .email-body {{
                padding: 20px;
            }}
            .email-body h1 {{
                font-size: 24px;
                color:#0c0221;
            }}
            .email-body p {{
                font-size: 16px;
                line-height: 1.5;
                color: #0c0221;
            }}
            .otp {{
                font-size: 24px;
                font-weight: bold;
                color: #007bff;
                text-align: center;
                margin: 20px 0;
            }}
            .email-footer {{
                text-align: center;
                font-size: 14px;
                color: #999;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                <img src="image/logo.png" alt="Product Logo">
            </div>
            <div class="email-body">
                <h1>Welcome to WEBFOXSHIELD!</h1>
                <p>Dear User,</p>
                <p>Thank you for registering with WEBFOXSHIELD. To complete your registration process, please use the following One-Time Password (OTP):</p>
                <div class="otp">{otp}</div>
                <p>This OTP is valid for a short period of time. If you did not request this OTP, please ignore this email.</p>
                <p>Best regards,<br>The WEBFOXSHIELD Team</p>
            </div>
            <div class="email-footer">
                &copy; 2024 WEBFOXSHIELD. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    #  email message
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = email

    # Attach the HTML body
    msg.attach(MIMEText(body, 'html'))

    #  logo image
    response = requests.get('http://127.0.0.1:5000/login')
    if response.status_code == 200:
        img_data = BytesIO(response.content)
        image = MIMEImage(img_data.read(), name='image/logo.png')
        image.add_header('Content-ID', '<logo>')
        msg.attach(image)

    # Send the email
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, [email], msg.as_string())
    server.quit()
