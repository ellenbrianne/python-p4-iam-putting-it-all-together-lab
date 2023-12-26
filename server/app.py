#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        try:
            form_json = request.get_json()
            new_user = User(username=form_json['username'], image_url=form_json['image_url'], bio=form_json['bio'])
            new_user.password_hash = form_json['password']
        
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return new_user.to_dict(), 201
        except:
            return "Server failed to process Signup for this user", 422

class CheckSession(Resource):
    
    def get(self):
        try:
            user = User.query.filter_by(id=session['user_id']).first()
            return user.to_dict(), 200
        except:
            return "User not logged in", 401

class Login(Resource):

    def post(self):
        try:
            user = User.query.filter_by(username=request.get_json()['username']).first()
            if user.authenticate(request.get_json()['password']):
                session['user_id'] = user.id
                return user.to_dict(), 200
        except:
            return "Incorrect Username or Password", 401

class Logout(Resource):
    
    def delete(self):
        if User.query.filter_by(id=session['user_id']).first():
            session['user_id'] = None
            return {}, 204
        else:
            return "Invalid request", 401


class RecipeIndex(Resource):
    
    def get(self):
        if session['user_id']:
            recipes = [r.to_dict() for r in Recipe.query.filter_by(user_id=session['user_id']).all()]
            return recipes, 200
        else:
            return {"message": "User not logged in"}, 401

    def post(self):
        if session['user_id']:
            try:
                json = request.get_json()
                new_r = Recipe(title=json['title'], instructions=json['instructions'], minutes_to_complete=json['minutes_to_complete'], user_id=session['user_id'])
                
                db.session.add(new_r)
                db.session.commit()

                return new_r.to_dict(), 201
            except:
                return {"message": "Invalid recipe"}, 422
        else:
            return {"message": "User not logged in"}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)