'''
ItemsCatalog.py

Implementation for the view of Catalog Item project for the Fullstack Web
development nanodegree at Udacity.com

Attributes:
    CLIENT_SECRETS_FILE (str): path to the google oauth api client secret json
    file

    CLIENT_ID (str): client_id for the google oauth api. Loaded from
    CLIENT_SECRETS_FILE

    app (Flask): The flask application Module

    engine (sqlalchemy.engine.Engine): sqlalchemy Engine object created with
    sqlalchemy's create_engine()

    dbsession (sqlalchemy.orm.session.sessionmaker): sqlalchemy sessionmaker
    factory

    session: (sqlalchemy.orm.session.sessionmaker): sql alchemy Session object
    created with the sessionmaker factory.
'''

from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import jsonify
from flask import url_for
from flask import make_response
from flask import flash
from flask import session as login_session
from flask import abort

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.exc import MultipleResultsFound
from sqlalchemy import desc

from db_setup import Base
from db_setup import User
from db_setup import Category
from db_setup import Item

from functools import wraps

import string
import random
import httplib2
import json
import requests

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

CLIENT_SECRETS_FILE = 'client_secrets.json'
CLIENT_ID = json.loads(
        open(CLIENT_SECRETS_FILE, 'r').read())['web']['client_id']

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

dbsession = sessionmaker(bind=engine)
session = dbsession()


def query_one_filter_by(model, **filter_by):
    '''
    Args:
        model (SomeMappedClass): Model defenition to pass to query()

        **filter_by: kwargs to pass to filter_by()

    Returns:
        Returns one result from database or calling abort()
    '''
    try:
        return session.query(model).filter_by(**filter_by).one()
    except NoResultFound:
        abort(404)
    except MultipleResultsFound:
        abort(500)


def login_required(f):
    '''
    Forces login required for sections that needs it

    Args:
        f (function): function to wrap

    Returns:
        decorated_function (function): the decorated decorated_function
    '''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        '''
        Checks that the user is in login_session thus logged in

        Args:
        *args: *args to pass to f
        **kwargs: **kwargs to pass to f
        '''
        if 'username' not in login_session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login')
def login():
    '''
    Shows the login page

    Returns:
        render_template: render_template object for login.html
    '''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def createUser(login_sessions):
    '''
    Creates a new user entry in the database

    Args:
        login_session (flask.session): login_session object for this project

    Returns:
        int: user id for the new user
    '''
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    '''
    Gets a user id from database based on email

    Args:
        email (str): e-mail to use for database lookup

    Returns:
        user id or None if user not found
    '''
    try:
        return session.query(User).filter_by(email=email).one().id
    except (NoResultFound, MultipleResultsFound) as e:
        return None


@app.route('/gconnect', methods=['post'])
def gconnect():
    '''
    Setup for google oauth authorization

    Returns:
        Error response object if it fails or welcome message on success.
    '''

    ''' Validate state token '''
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    ''' Obtain authorization code '''
    code = request.data

    try:
        ''' Upgrade the authorization code into a credentials object '''
        oauth_flow = flow_from_clientsecrets(CLIENT_SECRETS_FILE, scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    ''' Check that the access token is valid. '''
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    ''' If there was an error in the access token info, abort. '''
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    ''' Verify that the access token is used for the intended user. '''
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    ''' Verify that the access token is valid for this app. '''
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
                json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    ''' Store the access token in the session for later use. '''
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    ''' Get user info '''
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    ''' Store user info'''
    data = answer.json()
    login_session['username'] = data['name'] if 'name' in data else ''
    login_session['picture'] = data['picture'] if 'picture' in data else ''
    login_session['email'] = data['email'] if 'email' in data else ''
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    ''' Show welcome message and logged in flash message'''
    flash("You are now logged in as %s" % login_session['username'])
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 150px;
                             height: 150px;
                             border-radius: 150px;
                             -webkit-border-radius: 150px;
                             -moz-border-radius: 150px;"> '''
    return output


@app.route('/gdisconnect')
def gdisconnect():
    '''
    Disconnect google oauth authorization and delete stored data.

    Returns:
        Error object if user was not connected or redirect object to 'main'
        route
    '''
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
                json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    pep8sux = login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % pep8sux

    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        flash("You have been logged out!")
    else:
        flash("You where not logged in!")
    return redirect(url_for("main"))


@app.route('/catalog/JSON')
def mainJSON():
    '''
    Shows the main json endpoint with the full catalog listing

    Returns:
        json string with the whole catalog listing
    '''
    categories = session.query(Category).all()
    result = []
    for category in categories:
        category_serialized = category.serialize
        items = session.query(Item).filter_by(category_id=category.id).all()
        category_serialized['Item'] = [item.serialize for item in items]
        result.append(category_serialized)
    return jsonify({'Category': result})


@app.route('/catalog/<string:category_name>/JSON')
def itemsJSON(category_name):
    '''
    Shows a json listing of catalog items in the category supplied in the
    category_name argument

    Args:
        category_name (str): route parameter for Category.name

    Returns:
        json string with the catalog items in the category supplied
    '''
    category_id = query_one_filter_by(Category, name=category_name).id
    items = session.query(Item).filter_by(category_id=category_id)
    return jsonify(
            {category_name.capitalize(): [item.serialize for item in items]})


@app.route('/catalog/<string:category_name>/<string:item_name>/JSON')
def itemJSON(category_name, item_name):
    '''
    Shows a json item listing for one item in the catalog

    Args:
        category_name (str): route parameter for Category.name
        item_name (str): route parameter for Item.name

    Returns:
        json string with the item
    '''
    item = query_one_filter_by(Item, name=item_name)
    return jsonify({'Item': item.serialize})


@app.route('/')
@app.route('/catalog')
def main():
    '''
    The main route for both domain/ and domain/catalog. Shows item catalog
    with the latest added items

    Returns:
        render_template for items.html with latest added items
    '''
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc("id")).limit(10)
    items_categories = {}
    for item in items:
        items_categories[item.id] = query_one_filter_by(
                Category, id=item.category_id).name
    return render_template('items.html',
                           categories=categories,
                           items=items,
                           items_categories=items_categories,
                           header='Latest Items',
                           login_session=login_session)


@app.route('/catalog/<string:category_name>')
def items(category_name):
    '''
    Shows item catalog with the selected category

    Args:
        category_name (str): route parameter for Category.name

    Returns:
        render_template for items.html with items of selected category
    '''
    categories = session.query(Category).all()
    category_id = query_one_filter_by(Category, name=category_name).id
    items = session.query(Item).filter_by(category_id=category_id)
    items_categories = {}
    for item in items:
        items_categories[item.id] = query_one_filter_by(
                Category, id=item.category_id).name
    return render_template('items.html',
                           items=items,
                           categories=categories,
                           items_categories=items_categories,
                           header=category_name.capitalize(),
                           login_session=login_session)


@app.route('/catalog/<string:category_name>/<string:item_name>')
def item(category_name, item_name):
    '''
    Shows a item listing for one item in the catalog

    Args:
        category_name (str): route parameter for Category.name
        item_name (str): route parameter for Item.name

    Returns:
        render_template for item.html listing the selected item
    '''
    item = query_one_filter_by(Item, name=item_name)
    if 'username' in login_session:
        user = query_one_filter_by(User, name=login_session['username'])
    else:
        user = None
    print(user.id)
    print(item.user_id)
    return render_template('item.html',
                           item=item,
                           user=user,
                           login_session=login_session)


@app.route('/catalog/addItem', methods=['GET', 'POST'])
@login_required
def addItem():
    '''
    GET Shows a form to add item.

    POST adds a new item to the database. As we are using Item.name for routes
    we need to check the uniqueness of the item name.

    Returns
        For a successful POST we return a redirect object to the 'main' route.
        For GET or unsuccessful POST we return the additem.html template.
    '''
    if request.method == 'POST':
        addedItem = Item(name=request.form['name'],
                         user_id=login_session['user_id'],
                         category_id=request.form['category_select'],
                         description=request.form['description'])
        if session.query(Item).filter_by(
                name=addedItem.name).one_or_none() is None:
            session.add(addedItem)
            session.commit()
            return redirect(url_for('main'))
        else:
            flash("Item with that name already exist!")

    categories = session.query(Category).all()
    return render_template('additem.html',
                           categories=categories,
                           login_session=login_session)


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item_name):
    '''
    GET shows a form to edit item

    POST updates the item according to the edit form. As we are using Item.name
    for routes we need to check for uniqueness of the item name.

    Args:
        item_name (str): route parameter for Item.name to be edited

    Returns:
        For a successful POST or if user is not allowed to edit this item we
        return a redirect object to the 'main' route.
        For GET or unsuccessful POST we return the edititem.html template.
    '''
    item = query_one_filter_by(Item, name=item_name)
    if item.user_id != login_session['user_id']:
        flash('Not allowed to edit item created by other user!')
        return redirect(url_for('main'))

    if request.method == 'POST':
        item.name = request.form['name']
        item.category_id = request.form['category_select']
        item.description = request.form['description']
        if session.query(Item).filter_by(name=item.name).one_or_none() is None:
            session.add(item)
            session.commit()
            return redirect(url_for('main'))
        else:
            flash('Item with that name already exist!')

    categories = session.query(Category).all()
    return render_template('edititem.html',
                           item=item,
                           categories=categories,
                           login_session=login_session)


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item_name):
    '''
    GET shows form to confirm deletion of item

    POST shows deletes the item

    Returns:
        For POST or if user is not allowed to delete this item we return
        redirect object to 'main' route.
        GET return render_template for deleteitem.html to ask for
        confirmation.
    '''
    item = query_one_filter_by(Item, name=item_name)
    if item.user_id != login_session['user_id']:
        flash('Not allowed to delete item created by other user!')
        return redirect(url_for('main'))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('main'))
    else:
        return render_template('deleteitem.html',
                               item=item,
                               login_session=login_session)


@app.route('/catalog/addCategory', methods=['GET', 'POST'])
@login_required
def addCategory():
    '''
    GET show form for adding category

    POST add category. As we are using Category.name for routes we need to
    check for uniqueness

    Returns:
        For a successful POST we return a redirect object to the 'main' route.
        For GET or unsuccessful POST we return the addcategory.html
        render_template.
    '''
    if request.method == 'POST':
        addedCategory = Category(name=request.form['category'])
        if session.query(Category).filter_by(
                name=addedCategory.name).one_or_none() is None:
            session.add(addedCategory)
            session.commit()
            return redirect(url_for('main'))
        else:
            flash('Category exists!')

    categories = session.query(Category).all()
    return render_template('addcategory.html',
                           categories=categories,
                           login_session=login_session)


def forbidden_page(e):
    '''
    Error handler for 403 forbidden page

    Returns:
        returns template for error403.html
    '''
    return render_template('error403.html', login_session=login_session), 403


def page_not_found(e):
    '''
    Error handler for 404 page not found

    Returns:
        returns template for error404.html
    '''
    return render_template('error404.html', login_session=login_session), 404


def internal_server_error(e):
    '''
    Error handler for 500 Internal Server Error

    Returns:
        returns template for error500.html
    '''
    return render_template('error500.html', login_session=login_session), 500


def setup_app():
    '''
    Setup function for flask app
    '''
    app.secret_key = "super_secret_key"
    app.register_error_handler(403, forbidden_page)
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, internal_server_error)
    app.threaded = False
    app.debug = True


if __name__ == '__main__':
    setup_app()
    app.run(host='0.0.0.0', port=5000, threaded=False, debug=True)
