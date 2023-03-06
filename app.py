from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token




app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:@localhost:3306/essivi"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config[
    "SECRET_KEY"
] = "secret_key_for_auth"  # Clé secrète pour la génération de token JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)

db.init_app(app)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)

    return decorated
# login as  Admin
@app.route('/loginAdmin', methods=['POST'])

# Définition de la classe Agent
class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_agent = db.Column(db.String(20), unique=True, nullable=False)
    nom = db.Column(db.String(50), nullable=False)
    prenom = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    telephone = db.Column(db.String(15), nullable=False)
    adresse = db.Column(db.String(120), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"Agent('{self.id_agent}', '{self.nom}', '{self.prenom}', '{self.email}', '{self.telephone}', '{self.adresse}', '{self.latitude}', '{self.longitude}')"
    # route pour l'inscription d'un nouvel agent commercial
    @app.route('/agent/register', methods=['POST'])
    @token_required
    def register_agent(current_user):
        if not current_user.admin:
            return jsonify({'message': 'Action non autorisée!'})

        id_agent = request.json['id_agent']
        nom = request.json['nom']
        prenom = request.json['prenom']
        email = request.json['email']
        password = request.json['password']
        telephone = request.json['telephone']
        adresse = request.json['adresse']
        latitude = request.json['latitude']
        longitude = request.json['longitude']
        active = request.json['active']

        hashed_password = generate_password_hash(password, method='sha256')
        new_agent = Agent(id_agent=id_agent, nom=nom, prenom=prenom, email=email, password=hashed_password, telephone=telephone, adresse=adresse, latitude=latitude, longitude=longitude, active=active)
        db.session.add(new_agent)
        db.session.commit()

        return jsonify({'message': 'Nouvel agent commercial créé avec succès.'})

        # route pour l'authentification d'un agent commercial et la création d'un token JWT
    @app.route('/agent/login', methods=['POST'])
    def login_agent():
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
            return make_response('Authentification requise.', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        agent = Agent.query.filter_by(email=auth.username).first()

        if not agent:
            return make_response('Impossible de vérifier l\'agent commercial.', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(agent.password, auth.password):
            if agent.active:
                token = jwt.encode({'id_agent': agent.id_agent, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
                return jsonify({'token': token.decode('UTF-8')})
            else:
                return jsonify({'message': 'Le compte de l\'agent commercial n\'est pas activé.'})
        
        return make_response('Impossible de vérifier l\'agent commercial.', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    # route pour activer ou désactiver un compte agent commercial
    @app.route('/agent/<id_agent>/active', methods=['PUT'])
    @token_required
    def toggle_agent_active(current_user, id_agent):
        if not current_user.admin:
            return jsonify({'message': 'Action non autorisée!'})

        agent = Agent.query.filter_by(id_agent=id_agent).first()

        if not agent:
            return jsonify({'message': 'Agent commercial introuvable.'})

        agent.active = not agent.active
        db.session.commit()

        return jsonify({'message': 'Le compte de l\'agent commercial a été activé.' if agent.active else 'Le compte de l\'agent commercial a été désactivé.'})

# Définition de la classe Admin
class Admin(db.Model):
    id = Column(Integer, primary_key=True, autoincrement=True)
    name=db.Column(db.String(20),nullable=True)
    firstName=db.Column(db.String(50),nullable=True)
    email=db.Column(db.String(30),nullable=False)
    userName = db.Column(db.String(20), unique=True, nullable=True)
    password = db.Column(db.String(128), nullable=True)
    admin = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"Admin('{self.username}', '{self.password}')", 401
    @app.route('/loginAdmin',methods=['POST'])
    def loginAdmin():
        userName = request.json.get('userName', None)
        password = request.json.get('password', None)
        admin = Admin.query.filter_by(username=userName).first()
        if not admin:
            return jsonify({"msg": "Admin not found"}), 401
        if not check_password_hash(admin.password, password):
            return jsonify({"msg": "Invalid password"}), 401
        access_token = create_access_token(identity=admin.id)
        return jsonify({"access_token": access_token}), 200
    @app.route('/register', methods=['POST'])
    def register():

        name = request.json['name']
        firstName = request.json['firstName']
        userName= request.json['userName']
        email = request.json['email']
        password = request.json['password']
        admin= request.json['admin']
        hashed_password = generate_password_hash(password, method='sha256')
        new_Admin = Admin(name=name, firstName=firstName, email=email, password=hashed_password, userName=userName, admin=admin)
        db.session.add(new_Admin)
        db.session.commit()
        return jsonify({'message': 'Nouvel Admin créé avec succès.'})
        

    

# Définition pour la table Brand
class Brand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"<Brand {self.name}>"
    # Ajouter une marque d'eau
    @app.route('/admin/brand', methods=['POST'])
    @token_required
    def add_brand(current_user):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        name = request.json['name']
        description = request.json['description']

        new_brand = Brand(name=name, description=description)
        db.session.add(new_brand)
        db.session.commit()

        return jsonify({'message': 'La marque a été ajoutée avec succès!', 'brand': {'name': new_brand.name, 'description': new_brand.description}})

    # Modifier une marque d'eau
    @app.route('/admin/brand/<brand_id>', methods=['PUT'])
    @token_required
    def update_brand(current_user, brand_id):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        brand = Brand.query.get(brand_id)

        if not brand:
            return jsonify({'message': 'La marque d\'eau n\'a pas été trouvée!'})

        brand.name = request.json['name']
        brand.description = request.json['description']

        db.session.commit()

        return jsonify({'message': 'La marque a été mise à jour avec succès!', 'brand': {'name': brand.name, 'description': brand.description}})

    # Supprimer une marque d'eau
    @app.route('/admin/brand/<brand_id>', methods=['DELETE'])
    @token_required
    def delete_brand(current_user, brand_id):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        brand = Brand.query.get(brand_id)

        if not brand:
            return jsonify({'message': 'La marque d\'eau n\'a pas été trouvée!'})

        db.session.delete(brand)
        db.session.commit()

        return jsonify({'message': 'La marque a été supprimée avec succès!', 'brand': {'name': brand.name, 'description': brand.description}})

    # Récupérer toutes les marques d'eau
    @app.route('/brand', methods=['GET'])
    def get_brands(current_user):
        brands = Brand.query.all()

        output = []

        for brand in brands:
            brand_data = {}
            brand_data['id'] = brand.id
            brand_data['name'] = brand.name
            brand_data['description'] = brand.description
            output.append(brand_data)

        return jsonify({'brands': output})

# Définition pour la table Client
class Client(db.Model):
    __tablename__ = 'client'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(50), nullable=False)
    prenom = db.Column(db.String(50), nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    adresse = db.Column(db.String(200), nullable=False)

    def __init__(self, nom, prenom, telephone, adresse):
        self.nom = nom
        self.prenom = prenom
        self.telephone = telephone
        self.adresse = adresse

    def __repr__(self):
        return '<Client %r>' % self.nom
    # Récupérer tous les clients
    @app.route('/admin/clients', methods=['GET'])
    @token_required
    def get_clients(current_user):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        clients = Client.query.all()
        output = []
        for client in clients:
            client_data = {}
            client_data['id'] = client.id
            client_data['phone'] = client.phone
            client_data['address'] = client.address
            output.append(client_data)

        return jsonify({'clients': output})

    # Récupérer un client spécifique
    @app.route('/admin/clients/<client_id>', methods=['GET'])
    @token_required
    def get_client(current_user, client_id):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        client = Client.query.get(client_id)
        if not client:
            return jsonify({'message': 'Client introuvable!'})

        client_data = {}
        client_data['id'] = client.id
        client_data['phone'] = client.phone
        client_data['address'] = client.address

        return jsonify({'client': client_data})

    # Ajouter un nouveau client
    @app.route('/admin/clients', methods=['POST'])
    @token_required
    def add_client(current_user):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        data = request.get_json()
        new_client = Client(phone=data['phone'], address=data['address'])
        db.session.add(new_client)
        db.session.commit()

        return jsonify({'message': 'Nouveau client ajouté!'})

    # Modifier un client existant
    @app.route('/admin/clients/<client_id>', methods=['PUT'])
    @token_required
    def update_client(current_user, client_id):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        client = Client.query.get(client_id)
        if not client:
            return jsonify({'message': 'Client introuvable!'})

        data = request.get_json()
        client.phone = data['phone']
        client.address = data['address']
        db.session.commit()

        return jsonify({'message': 'Client mis à jour!'})

    # Supprimer un client existant
    @app.route('/admin/clients/<client_id>', methods=['DELETE'])
    @token_required
    def delete_client(current_user, client_id):
        if not current_user.is_admin:
            return jsonify({'message': 'Vous n\'êtes pas autorisé à effectuer cette action!'})

        client = Client.query.get(client_id)
        if not client:
            return jsonify({'message': 'Client introuvable!'})

        db.session.delete(client)
        db.session.commit()

        return jsonify({'message': 'Client supprimé!'})


# Création des tables dans la base de données
db.create_all()

if __name__ == '__main__':
    app.run()
