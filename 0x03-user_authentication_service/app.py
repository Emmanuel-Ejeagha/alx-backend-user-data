#!/usr/bin/env python3

"""Basic flask application"""
import flask
from flask import Flask, jsonify, request, make_response, redirect
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


# Home
@app.route('/', methods=['GET'], strict_slashes=False)
def first_req() -> str:
    """Return json str"""
    return jsonify({"message": "Bienvenue"})


# User registration
@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """register user"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


# User Login
@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Login users"""
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if not session_id:
            flask.abort(401)
        response = make_response(jsonify({"email": email,
                                          "message": "logged in"}))
        response.set_cookie("session_id", session_id)
        return response
    flask.abort(401)


# User logout
@app.route('/sessions', methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """logout the users"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        return redirect('/')


# User's profile
@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Get users profile"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        flask.abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        flask.abort(403)


# Reset password
@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Reset password"""
    email = request.form.get('email')
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token}), 200
    except ValueError:
        flask.abort(403)


# Update Password
@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """update password route"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, password)
    except ValueError:
        flask.abort(403)
    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
