import os
from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity

# --- Initialize app and CORS ---
app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:3000",  # React local dev
    "http://localhost:5173",  # Vite local dev
    "http://127.0.0.1:3000",
    "https://uat.churpay.com",
    "https://churpay.com"
], supports_credentials=True)

# --- Config ---
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///churpay.db"
app.config["JWT_SECRET_KEY"] = "super-secret-poi"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Models ---
# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="member")  # "member", "church", "admin"
    account_number = db.Column(db.Integer, unique=True, nullable=False)  # <<--- NEW FIELD

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def generate_next_account_number(role):
    if role == "church":
        last_church = User.query.filter_by(role="church").order_by(User.account_number.desc()).first()
        if last_church and last_church.account_number >= 2000000:
            return last_church.account_number + 1
        return 2000000  # First church account
    else:
        last_member = User.query.filter(User.role != "church").order_by(User.account_number.desc()).first()
        if last_member and last_member.account_number >= 1000000:
            return last_member.account_number + 1
        return 1000000  # First member account


class Church(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    logo_url = db.Column(db.String(256))
    # Add more fields if you need (address, phone, etc)

# --- Payout Request Model ---
class PayoutRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey('church.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    bank_name = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(120), nullable=False)
    account_holder = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending') # 'pending', 'approved', 'rejected'
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# --- DUMMY DATA (keep your demo data for now) ---
projects = [
    {
        "id": 1,
        "title": "Roof Repair",
        "church": "GCC Faith Center",
        "description": "Help us fix our church roof after storm damage.",
        "goal": 10000,
        "raised": 3500,
        "status": "Active",
    },
    {
        "id": 101,
        "title": "Youth Camp",
        "church": "Bethel Life",
        "description": "Sponsor our annual youth retreat and change lives!",
        "goal": 6000,
        "raised": 2200,
        "status": "Pending",
    },
]

donations = []

# --- API ROUTES ---

# File Uploads
@app.route("/api/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"filename": filename, "url": f"/uploads/{filename}"})
    return jsonify({"error": "Invalid file"}), 400

@app.route("/uploads/<filename>")
def get_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Donations
@app.route("/api/donations", methods=["GET"])
def get_donations():
    return jsonify(donations)

@app.route("/api/donations", methods=["POST"])
def create_donation():
    data = request.json
    donations.append(data)
    return jsonify(data), 201

# Projects
@app.route("/api/projects", methods=["GET"])
def get_projects():
    return jsonify(projects)

@app.route("/api/projects", methods=["POST"])
def add_project():
    data = request.json
    data["id"] = max(p["id"] for p in projects) + 1 if projects else 1
    projects.append(data)
    return jsonify(data), 201

@app.route("/api/projects/<int:project_id>/status", methods=["PATCH"])
def update_project_status(project_id):
    data = request.json
    new_status = data.get("status")
    for p in projects:
        if p["id"] == project_id:
            p["status"] = new_status
            return jsonify(p)
    return jsonify({"error": "Project not found"}), 404

# --- User Registration & Auth ---
@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return '', 200
    data = request.json
    allowed_roles = {"member", "church", "admin"}
    if User.query.filter_by(email=data.get("email")).first():
        return jsonify({"error": "Email already exists"}), 409
    reg_name = data.get("name") or data.get("church_name")
    if not reg_name or not data.get("email") or not data.get("password") or not data.get("role"):
        return jsonify({"error": "All fields are required"}), 400
    if data["role"] not in allowed_roles:
        return jsonify({"error": "Invalid role"}), 400
    # --- Generate account number here ---
    next_account_number = generate_next_account_number(data["role"])
    user = User(name=reg_name, email=data["email"], role=data["role"], account_number=next_account_number)
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Registered!", "account_number": next_account_number})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()
    if user and user.check_password(data["password"]):
        token = create_access_token(identity=str(user.id))
        return jsonify({
            "token": token,
            "role": user.role,
            "name": user.name,
            "email": user.email,
            "account_number": user.account_number  # <<--- Add this
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    return jsonify({
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "account_number": user.account_number  # <<--- Add this
    })

# Create a new church
@app.route("/api/churches", methods=["POST"])
def create_church():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    logo_url = data.get("logo_url", "")
    if not name or not email:
        return jsonify({"error": "Name and email required"}), 400
    if Church.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409
    church = Church(name=name, email=email, logo_url=logo_url)
    db.session.add(church)
    db.session.commit()
    return jsonify({"msg": "Church created", "church_id": church.id})

# Update church logo
@app.route("/api/church/<int:church_id>/logo", methods=["POST"])
def update_church_logo(church_id):
    data = request.json
    url = data.get("logo_url")
    church = Church.query.get(church_id)
    if not church:
        return jsonify({"error": "Church not found"}), 404
    church.logo_url = url
    db.session.commit()
    return jsonify({"msg": "Logo updated", "logo_url": url})

# Get all churches
@app.route("/api/churches", methods=["GET"])
def get_churches():
    all_churches = Church.query.all()
    out = []
    for c in all_churches:
        out.append({
            "id": c.id,
            "name": c.name,
            "email": c.email,
            "logo_url": c.logo_url
        })
    return jsonify(out)

# --- Church Payout Endpoints ---

# 1. Church requests a payout
@app.route("/api/church/request-payout", methods=["POST"])
@jwt_required()
def request_payout():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.role != "church":
        return jsonify({"error": "Only churches can request payouts."}), 403
    data = request.json
    required = ["amount", "bank_name", "account_number", "account_holder"]
    if not all(x in data and data[x] for x in required):
        return jsonify({"error": "Missing info."}), 400
    payout = PayoutRequest(
        church_id=user.id,
        amount=data["amount"],
        bank_name=data["bank_name"],
        account_number=data["account_number"],
        account_holder=data["account_holder"],
    )
    db.session.add(payout)
    db.session.commit()
    return jsonify({"msg": "Payout request submitted!", "payout_id": payout.id})

# 2. Church view their payout history
@app.route("/api/church/my-payouts", methods=["GET"])
@jwt_required()
def my_payouts():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.role != "church":
        return jsonify({"error": "Only churches can view payouts."}), 403
    payouts = PayoutRequest.query.filter_by(church_id=user.id).order_by(PayoutRequest.created_at.desc()).all()
    out = []
    for p in payouts:
        out.append({
            "id": p.id,
            "amount": p.amount,
            "bank_name": p.bank_name,
            "account_number": p.account_number,
            "account_holder": p.account_holder,
            "status": p.status,
            "created_at": p.created_at
        })
    return jsonify(out)

# 3. Admin view all payout requests
@app.route("/api/admin/payout-requests", methods=["GET"])
@jwt_required()
def all_payout_requests():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.role != "admin":
        return jsonify({"error": "Only admin can view payout requests."}), 403
    payouts = PayoutRequest.query.order_by(PayoutRequest.created_at.desc()).all()
    out = []
    for p in payouts:
        church = Church.query.get(p.church_id)
        out.append({
            "id": p.id,
            "church": church.name if church else "",
            "amount": p.amount,
            "bank_name": p.bank_name,
            "account_number": p.account_number,
            "account_holder": p.account_holder,
            "status": p.status,
            "created_at": p.created_at
        })
    return jsonify(out)

# 4. Admin approve/reject payout
@app.route("/api/admin/approve-payout", methods=["POST"])
@jwt_required()
def approve_payout():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.role != "admin":
        return jsonify({"error": "Only admin can approve payouts."}), 403
    data = request.json
    payout_id = data.get("payout_id")
    payout = PayoutRequest.query.get(payout_id)
    if not payout:
        return jsonify({"error": "Payout request not found."}), 404
    payout.status = "approved"
    db.session.commit()
    return jsonify({"msg": "Payout marked as approved."})

@app.route("/api/admin/reject-payout", methods=["POST"])
@jwt_required()
def reject_payout():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.role != "admin":
        return jsonify({"error": "Only admin can reject payouts."}), 403
    data = request.json
    payout_id = data.get("payout_id")
    payout = PayoutRequest.query.get(payout_id)
    if not payout:
        return jsonify({"error": "Payout request not found."}), 404
    payout.status = "rejected"
    db.session.commit()
    return jsonify({"msg": "Payout marked as rejected."})

@app.route("/api/member/dashboard", methods=["GET"])
@jwt_required()
def member_dashboard():
    user_id = get_jwt_identity()
    # You can fetch user data from the DB if you want
    return jsonify({
        "welcome": "Welcome to your member dashboard!",
        "projects_supported": 3,
        "total_given": 1500
    }), 200

# --- Main entry ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)