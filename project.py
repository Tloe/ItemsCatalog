from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import jsonify
from flask import url_for
from flask import make_response
from flask import flash
from flask import session as login_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, User, Category, Item
import string
import random
import httplib2
import json
import requests

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

app = Flask(__name__)

CLIENT_ID = json.loads(
        open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CatalogProject"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def createUser(login_sessions):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    user = session.query(User).filter_by(email=email).one()
    return user.id


@app.route('/gconnect', methods=['post'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
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

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px;
                             height: 300px;
                             border-radius: 150px;
                             -webkit-border-radius: 150px;
                             -moz-border-radius: 150px;"> '''
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
                json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session[
            'access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash("You have been logged out!")
    else:
        flash("You where not logged in!")
    return redirect(url_for("main"))


@app.route('/catalog/JSON')
def mainJSON():
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
    category_id = session.query(Category).filter_by(
            name=category_name).one().id
    items = session.query(Item).filter_by(category_id=category_id)
    return jsonify(
            {category_name.capitalize(): [item.serialize for item in items]})


@app.route('/catalog/<string:category_name>/<string:item_name>/JSON')
def itemJSON(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    return jsonify({'Item': item.serialize})


@app.route('/')
@app.route('/catalog')
def main():
    categories = session.query(Category).all()
    items = session.query(Item).order_by("id").limit(10)
    items_categories = {}
    for item in items:
        items_categories[item.id] = session.query(Category).filter_by(
                id=item.category_id).one().name
    return render_template('items.html',
                           categories=categories,
                           items=items,
                           items_categories=items_categories,
                           header='Latest Items',
                           login_session=login_session)


@app.route('/catalog/<string:category_name>')
def items(category_name):
    categories = session.query(Category).all()
    category_id = session.query(Category).filter_by(
            name=category_name).one().id
    items = session.query(Item).filter_by(category_id=category_id)
    items_categories = {}
    for item in items:
        items_categories[item.id] = session.query(Category).filter_by(
                id=item.category_id).one().name
    return render_template('items.html',
                           items=items,
                           categories=categories,
                           items_categories=items_categories,
                           header=category_name.capitalize(),
                           login_session=login_session)


@app.route('/catalog/<string:category_name>/<string:item_name>')
def item(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('item.html',
                           item=item,
                           login_session=login_session)


@app.route('/catalog/addItem', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        addedItem = Item(name=request.form['name'],
                         user_id=login_session['user_id'],
                         category_id=request.form['category_select'],
                         description=request.form['description'])
        session.add(addedItem)
        session.commit()
        return redirect(url_for('main'))
    else:
        categories = session.query(Category).all()
        return render_template('additem.html',
                               categories=categories,
                               login_session=login_session)


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    if 'username' not in login_session:
        return redirect(url_for('login'))
    item = session.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        item.name = request.form['name']
        item.category_id = request.form['category_select']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        return redirect(url_for('main'))
    else:
        categories = session.query(Category).all()
        return render_template('edititem.html',
                               item=item,
                               categories=categories,
                               login_session=login_session)


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):
    if 'username' not in login_session:
        return redirect(url_for('login'))
    item = session.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('main'))
    else:
        return render_template('deleteitem.html',
                               item=item,
                               login_session=login_session)


@app.route('/catalog/addCategory', methods=['GET', 'POST'])
def addCategory():
    if 'username' not in login_session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        addedCategory = Category(name=request.form['category'])
        session.add(addedCategory)
        session.commit()
        return redirect(url_for('main'))
    else:
        categories = session.query(Category).all()
        return render_template('addcategory.html',
                               categories=categories,
                               login_session=login_session)


if __name__ == '__main__':
    app.secret_key = "super_secret_key"
    app.run(host='0.0.0.0', port=5000, threaded=False, debug=True)
