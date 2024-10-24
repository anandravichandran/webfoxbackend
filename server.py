# from flask import Flask
# from routes.auth import auth_routes
# from routes.functions import function_routes
# from flask_cors import CORS

# app = Flask(__name__)
# CORS(app)

# # Registering routes
# app.register_blueprint(auth_routes)
# app.register_blueprint(function_routes)

# if __name__ == '__main__':
#     app.run(debug=True)
#     app.run(host="0.0.0.0", port=5000, debug=True)
    
from flask import Flask
from routes.auth import auth_routes
from routes.functions import function_routes
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS for specific origins (localhost:3000 in this case) for all routes
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# Registering blueprints for different route modules
app.register_blueprint(auth_routes)
app.register_blueprint(function_routes)

if __name__ == '__main__':
    # Run the app with one call, listening on all IP addresses on port 5000
    app.run(host="0.0.0.0", port=5000, debug=True)
