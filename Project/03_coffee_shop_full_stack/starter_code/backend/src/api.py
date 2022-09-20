from flask import Flask, request, jsonify, abort
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink, db
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
'''
# db_drop_and_create_all()

# ROUTES
'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks')
def get_drinks():
    selection = Drink.query.all()

    if selection is None:
        abort(404)

    drinks = [s.short() for s in selection]

    return jsonify({
        'success': True,
        'drinks': drinks
    }), 200


'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    if payload:
        selection = Drink.query.all()
        formatted_selection = [s.long() for s in selection]

        return jsonify({
            'success': True,
            'drinks': formatted_selection
        }), 200


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink(payload):
    if payload:
        body = request.get_json()
        if body:

            new_title = body.get('title', None)
            new_recipe = json.dumps(body.get('recipe', None))
            if new_title or new_recipe:
                try:
                    drink = Drink(title=new_title, recipe=new_recipe)
                    drink.insert()

                    selection = Drink.query.filter_by(title=new_title).one_or_none()

                    return jsonify({
                        'success': True,
                        'drinks': [selection.long()]
                    }), 200

                except:
                    abort(405)
                finally:
                    db.session.close()
            else:
                abort(400)
        else:
            abort(400)


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, drink_id):
    if payload:
        drink = Drink.query.get(drink_id)
        if drink:
            body = request.get_json()

            if body:
                title = body.get('title', None)
                recipe = json.dumps(body.get('recipe', None))

                try:
                    if title and recipe:
                        drink.title = title
                        drink.recipe = recipe
                        drink.update()
                    elif recipe:
                        drink.recipe = recipe
                        drink.update()
                    elif title:
                        drink.title = title
                        drink.update()
                    else:
                        abort(400)

                    updated_drink = Drink.query.get(drink_id)

                    return jsonify({
                        'success': True,
                        'drinks': [updated_drink.long()]
                    }), 200
                except:
                    abort(405)
                finally:
                    db.session.close()
            else:
                abort(400)
        else:
            abort(404)


'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, drink_id):
    if payload:
        drink = Drink.query.get(drink_id)

        if drink:
            try:
                drink.delete()

                return jsonify({
                    'success': True,
                    'delete': drink_id
                }), 200
            except:
                abort(405)
            finally:
                db.session.close()
        else:
            abort(404)


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
'''

'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''


@app.errorhandler(400)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "bad request"
    }), 400



@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": "method not allowed"
    }), 405


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''


@app.errorhandler(AuthError)
def auth_error(error):
    response = error
    return jsonify({
        "success": False,
        "error": response.status_code,
        "message": response.error
    }), response.status_code
