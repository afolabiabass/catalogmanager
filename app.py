from flask import Flask, render_template, request, redirect, abort, jsonify, g, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Catalog, CatalogItem, User
from werkzeug.utils import secure_filename

from flask import session as auth_session
import random, string
import httplib2, urllib
import json
from passlib.apps import custom_app_context as pwd_context
from functools import wraps

engine = create_engine('postgres:///catalogdb')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


@app.before_request
def load_user():
    if 'user' in auth_session:
        user = session.query(User).filter_by(name=auth_session['user']).first()
    else:
        user = {'name': 'Guest'}
    g.user = user


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in auth_session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    catalogs = session.query(Catalog).all()
    return render_template('index.html', catalogs=catalogs)


@app.route('/catalog')
@login_required
def index_catalog():
    """View all catalog for the current user."""
    user = session.query(User).filter_by(email=auth_session['email']).first()
    catalogs = session.query(Catalog).filter_by(user_id=user.id).all()
    return render_template('catalog/index.html', catalogs=catalogs)


@app.route('/catalog/create', methods=['GET', 'POST'])
@login_required
def create_catalog():
    """Create a new catalog for the current user."""
    user = session.query(User).filter_by(email=auth_session['email']).first()
    if request.method == 'POST':
        catalog = Catalog(
            name=request.form['name'],
            description=request.form['description'],
            user_id=user.id
        )
        session.add(catalog)
        session.commit()
        return redirect(url_for('index_catalog'))
    else:
        catalogs = session.query(Catalog).filter_by(user_id=user.id).limit(5)
        return render_template('catalog/create.html', catalogs=catalogs)


@app.route('/catalog/<int:catalog_id>')
def show_catalog(catalog_id):
    """Show Catalog details to any requesting user."""
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    return render_template('catalog/show.html', catalog=catalog)


@app.route('/catalog/<int:catalog_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_catalog(catalog_id):
    """Update catalog if owner is the current user."""
    user = session.query(User).filter_by(email=auth_session['email']).first()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    catalogs = session.query(Catalog).filter_by(user_id=user.id).all()

    if g.user != catalog.user.name:
        return redirect(url_for('index'))

    if request.method == 'POST':
        catalog.name = request.form['name']
        catalog.description = request.form['description']
        return redirect(url_for('show_catalog', catalog_id=catalog.id))
    else:
        return render_template('catalog/edit.html', catalog=catalog, catalogs=catalogs)


@app.route('/catalog/<int:catalog_id>/delete', methods=['POST'])
@login_required
def delete_catalog(catalog_id):
    """Delete catalog if owner is the current user."""
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()

    if g.user != catalog.user.name:
        return redirect(url_for('index'))

    session.delete(catalog)
    session.commit()
    return redirect(url_for('index_catalog'))


@app.route('/api/v1/catalog')
def catalog_json():
    """Return json of all Catalog details to any requesting user."""
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs=[c.serialize for c in catalogs])


@app.route('/api/v1/catalog/<int:catalog_id>')
def catalog_single_json(catalog_id):
    """Return json of single Catalog details to any requesting user."""
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    return jsonify(catalog.serialize)


@app.route('/items')
@login_required
def index_items():
    user = session.query(User).filter_by(email=auth_session['email']).first()
    items = session.query(CatalogItem).filter_by(user_id=user.id).all()
    return render_template('items/index.html', items=items)


@app.route('/items/create', methods=['GET', 'POST'])
@login_required
def create_item():
    """Create a new catalog item for the current user."""
    user = session.query(User).filter_by(email=auth_session['email']).first()
    if request.method == 'POST':
        item = CatalogItem(
            name=request.form['name'],
            description=request.form['description'],
            user_id=user.id,
            catalog_id=request.form['catalog']
        )
        session.add(item)
        session.commit()
        return redirect(url_for('index_items'))
    else:
        catalogs = session.query(Catalog).filter_by(user_id=user.id).all()
        items = session.query(CatalogItem).filter_by(user_id=user.id).limit(5)
        return render_template('items/create.html', items=items, catalogs=catalogs)


@app.route('/items/<int:item_id>')
def show_item(item_id):
    """Show Catalog item details to any requesting user."""
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    return render_template('items/show.html', item=item)


@app.route('/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    """Update catalog item if owner is the current user."""
    user = session.query(User).filter_by(email=auth_session['email']).first()
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    items = session.query(CatalogItem).filter_by(user_id=user.id).all()

    if g.user != item.user.name:
        return redirect(url_for('index'))

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.catalog_id = request.form['catalog']
        return redirect(url_for('show_item', item_id=item.id))
    else:
        catalogs = session.query(Catalog).filter_by(user_id=user.id).all()
        return render_template('items/edit.html', item=item, items=items, catalogs=catalogs)


@app.route('/items/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(item_id):
    """Delete catalog item if owner is the current user."""
    item = session.query(CatalogItem).filter_by(id=item_id).one()

    if g.user != item.user.name:
        return redirect(url_for('index'))

    session.delete(item)
    session.commit()
    return redirect(url_for('index_items'))


@app.route('/api/v1/items')
def items_json():
    """Return json of all Catalog item details to any requesting user."""
    items = session.query(CatalogItem).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/api/v1/items/<int:item_id>')
def item_single_json(item_id):
    """Return json of single Catalog item details to any requesting user."""
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    return jsonify(item.serialize)


@app.route('/login', methods=['GET', 'POST'])
def login():
    token = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    auth_session['session_token'] = token
    if request.method == 'GET':
        if 'user' in auth_session:
            redirect(url_for('index'))
        else:
            return render_template('login.html')
    elif request.method == 'POST':
        user = session.query(User).filter_by(email=request.form['email']).first()
        if not user or not pwd_context.verify(request.form['password'], user.password):
            error = 'Invalid email address or password. Please try again!'
            return render_template('login.html', error=error)
        auth_session['user'] = user.name
        auth_session['token'] = token
        auth_session['email'] = user.email
        return redirect(url_for('index'))


@app.route('/login/google', methods=['GET', 'POST'])
def google_login():
    google_client_id = '941992718587-ugr9hm493de7cgsm60e49ic51t6mlc2g.apps.googleusercontent.com'
    redirect_uri = 'http%3A%2F%2Flocalhost%3A5000%2Flogin%2Fgoogle%2Fcallback'

    token = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    auth_session['session_token'] = token

    url = 'https://accounts.google.com/o/oauth2/v2/auth?' \
          'response_type=code' \
          '&scope=openid%20email%20profile'\
          '&access_type=offline' \
          '&prompt=select_account' \
          '&client_id={}' \
          '&redirect_uri={}' \
          '&state={}'.format(google_client_id, redirect_uri, token)

    params = ''

    headers = {'Content-type': 'text/html', 'Accept': 'text/plain', 'Content-length': str(len(params))}

    h = httplib2.Http()
    h.follow_all_redirects = True
    response, content = h.request(url, 'POST', body=params, headers=headers)

    return content


@app.route('/login/google/callback', methods=['GET', 'POST'])
def google_login_callback():
    if request.args['code'] and request.args['state'] == auth_session['session_token']:
        """request for long lived access token"""
        google_client_id = '941992718587-ugr9hm493de7cgsm60e49ic51t6mlc2g.apps.googleusercontent.com'
        google_client_secret = 'axBd62FzjIx-LYe9Sle30wlN'
        redirect_uri = 'http://localhost:5000/login/google/callback'

        url = 'https://www.googleapis.com/oauth2/v4/token'
        params = urllib.urlencode({
            'code': request.args['code'],
            'client_id': google_client_id,
            'client_secret': google_client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        })
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain', 'Content-length': str(len(params))}

        h = httplib2.Http()
        h.follow_all_redirects = True
        response, content = h.request(url, 'POST', body=params, headers=headers)
        data = json.loads(content)
        access_token = data['access_token']
        expires_at = int(data['expires_in'])

        user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token={}'.format(access_token)
        response, content = h.request(user_info_url, 'GET')
        data = json.loads(content)

        user = session.query(User).filter_by(email=data['email']).first()
        if user:
            user.name = data['given_name'] + ' ' + data['family_name']
            user.token = access_token
            # user.expires_at = expires_at
            auth_session['user'] = user.name
            auth_session['email'] = user.email
            return redirect(url_for('index'))
        else:
            name = data['given_name'] + ' ' + data['family_name']
            user = User(name=name, email=data['email'], token=access_token)
            session.add(user)
            session.commit()
            auth_session['user'] = data['name']
            auth_session['email'] = data['email']
            return redirect(url_for('index'))
    else:
        # send user back to login page with error message
        return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(name=request.form['name'], email=request.form[
            'email'], password=pwd_context.encrypt(request.form['password']))
        session.add(user)
        session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('register.html')


@app.route('/logout')
def logout():
    auth_session.pop('user', None)
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
