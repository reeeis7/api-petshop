from flask import Flask, render_template, request, jsonify
import jwt
from functools import wraps
from jwt import ExpiredSignatureError, InvalidTokenError
from produtos import products

app = Flask(__name__)
SECRET_KEY = 'Gabriel'

USER_DB = [
    {'id': 1, 'name': 'Gabriel', 'password': '1234', 'admin': True},
    {'id': 2, 'name': 'Ga', 'password': '12345', 'admin': False}
]

def encontrar_usuario(username, password):
    for user in USER_DB:
        if user['name'] == username and user['password'] == password:
            return user
    return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Token é necessário!"}), 403

        parts = auth_header.split()
        if parts[0].lower() != 'bearer' or len(parts) != 2:
            return jsonify({"message": "Formato do token inválido!"}), 401

        token = parts[1]
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except ExpiredSignatureError:
            return jsonify({"message": "Token expirado!"}), 401
        except InvalidTokenError:
            return jsonify({"message": "Token inválido!"}), 403

        return f(*args, **kwargs)
    return decorated

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')

    user = encontrar_usuario(username, password)

    if user:
        payload = {
            'user': user['name'],
            'admin': user['admin']
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        if request.is_json:
            return jsonify({'token': token, 'user': user['name'], 'admin': user['admin']})

        return render_template('admin.html' if user['admin'] else 'home.html', user=user, token=token)
    else:
        if request.is_json:
            return jsonify({'message': 'Credenciais inválidas'}), 401
        return render_template('erro_login.html')

@app.route('/produtos')
def produtos_view():
    return render_template('produtos.html', produtos=products)

@app.route('/products', methods=['GET'])
@token_required
def get_products():
    resultado = products.copy()
    description_part = request.args.get('description_part')
    if description_part:
        resultado = [p for p in resultado if description_part.lower() in p['product_description'].lower()]

    if request.args.get('preco_asc') == 'true':
        resultado.sort(key=lambda x: x['product_price'])
    elif request.args.get('preco_desc') == 'true':
        resultado.sort(key=lambda x: x['product_price'], reverse=True)

    return jsonify(resultado)

@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product_by_id(product_id):
    produto = next((p for p in products if p['id'] == product_id), None)
    if produto:
        return jsonify(produto)
    return jsonify({"message": "Produto não encontrado!"}), 404

if __name__ == '__main__':
    app.run(debug=True)
