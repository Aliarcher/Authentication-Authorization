from flasgger import Swagger
from datetime import timedelta

from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "Secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
swagger = Swagger(app)


@app.route("/login", methods=["POST"])
def login():
    """
    A simple login endpoint
    ---
    parameters:
      - name: username
        in: query
        type: string
        required: true
        description: The username paramether
      - name: password
        in: query
        type: string
        required: true
        description: The password paramether  
    responses:
      401:
        description: Bad username or password
        examples: 
            'Bad username or password'
        schema:
           type: string
      200:
        description: Access Token and Refresh Token
        examples:
        schema:
           type: string
    """
    username = request.args.get("username", None)
    password = request.args.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401
    
    access_token = create_access_token(identity="test", fresh=True)
    refresh_token = create_refresh_token(identity="test")
    return jsonify(access_token=access_token, refresh_token=refresh_token)


# We are using the `refresh=True` options in jwt_required to only allow
# refresh tokens to access this route.
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@app.route("/public", methods=["GET"])
def public():
    return jsonify(foo="bar")

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(foo="bar")


if __name__ == "__main__":
    app.run(port=8090)