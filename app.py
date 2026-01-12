import os
import io
import tempfile
from datetime import datetime, timedelta
from functools import wraps

# MongoDB and BSON for ID handling
from pymongo import MongoClient
from bson.objectid import ObjectId

from flask import (
    Flask, render_template, request, jsonify, 
    flash, redirect, url_for, session, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# --- 1. Basic Configuration ---
app.config['SECRET_KEY'] = 'HeartScript_Secret_Admin_2025_Key'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure folders exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Allowed files extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- 2. MongoDB Atlas Setup (Replaces Firestore) ---
# Connection String updated with your credentials
MONGO_URI = "mongodb+srv://heartscript025_db_user:HeartScript@Admin2025@heartscript.secaej6.mongodb.net/?appName=HeartScript"
try:
    client = MongoClient(MONGO_URI)
    m_db = client.heartscript_db # MongoDB Database name
    mg_users = m_db.users
    mg_products = m_db.products
    mg_orders = m_db.orders
    print("✅ MongoDB Atlas Connected Successfully!")
except Exception as e:
    print(f"⚠️ MongoDB Connection Error: {e}")

# --- 3. Local Database Configuration (SQLite) ---
# Railway par '/tmp' ya current directory use karna better hota hai
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'heartscript_v2.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- 4. Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    pincode = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(20), default='customer')
    ans1 = db.Column(db.String(100), nullable=True)
    ans2 = db.Column(db.String(100), nullable=True)
    ans3 = db.Column(db.String(100), nullable=True)
    ans4 = db.Column(db.String(100), nullable=True)
    ans5 = db.Column(db.String(100), nullable=True)
    ans6 = db.Column(db.String(100), nullable=True)
    ans7 = db.Column(db.String(100), nullable=True)
    profile_pic = db.Column(db.String(500), default="/static/uploads/default_avatar.png")
    orders = db.relationship('Order', backref='customer', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    products = db.relationship('Product', backref='category_ref', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    # Supporting 3 Images now
    image_url = db.Column(db.String(500), default="https://via.placeholder.com/300")
    image_url2 = db.Column(db.String(500), default="")
    image_url3 = db.Column(db.String(500), default="")
    description = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    house_no = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=False)
    landmark = db.Column(db.String(100), nullable=True)
    pincode = db.Column(db.String(10), nullable=True)
    custom_details = db.Column(db.Text, nullable=True)
    total = db.Column(db.String(20), nullable=False)
    items = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pending")
    delivery_mode = db.Column(db.String(20), default="self")
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

# --- 5. Auth Decorators & Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to proceed.", "info")
            return redirect(url_for('user_login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash("Account error. Please login again.", "danger")
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(request.form.get('password'))

        ans_data = {
            'ans1': request.form.get('ans1', '').strip().lower(),
            'ans2': request.form.get('ans2', '').strip().lower(),
            'ans3': request.form.get('ans3', '').strip().lower(),
            'ans4': request.form.get('ans4', '').strip().lower(),
            'ans5': request.form.get('ans5', '').strip().lower(),
            'ans6': request.form.get('ans6', '').strip().lower(),
            'ans7': request.form.get('ans7', '').strip().lower()
        }

        filled_answers = [v for v in ans_data.values() if v != '']
        if len(filled_answers) < 3:
            flash("Please answer at least 3 security questions!", "warning")
            return redirect(url_for('register'))

        new_user = User(
            username=request.form.get('username'), 
            email=email,
            password_hash=hashed_pw, 
            phone=request.form.get('phone'),
            address=request.form.get('address'), 
            pincode=request.form.get('pincode'),
            **ans_data
        )
        db.session.add(new_user)
        db.session.commit()

        # MongoDB Sync
        try:
            mg_users.update_one(
                {'email': email},
                {'$set': {
                    'username': request.form.get('username'), 
                    'email': email,
                    'phone': request.form.get('phone'), 
                    'address': request.form.get('address'),
                    'pincode': request.form.get('pincode'), 
                    'role': 'customer',
                    'created_at': datetime.utcnow()
                }},
                upsert=True
            )
        except Exception as e:
            print(f"MongoDB Sync Error: {e}")

        flash("Account created! Welcome to HeartScript.", "success")
        return redirect(url_for('user_login'))
    return render_template('register.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.username
            session['user_email'] = user.email
            session['user_profile_pic'] = user.profile_pic
            return redirect(url_for('home'))
        flash("Invalid email or password.", "danger")
    return render_template('user_login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for('forgot_password'))

        provided_answers = [request.form.get(f'ans{i}', '').strip().lower() for i in range(1, 8)]
        db_answers = [user.ans1, user.ans2, user.ans3, user.ans4, user.ans5, user.ans6, user.ans7]
        matches = sum(1 for p, d in zip(provided_answers, db_answers) if p and d and p == d)

        if matches >= 3:
            new_password = request.form.get('new_password')
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Success! Password updated.", "success")
            return redirect(url_for('user_login'))
        else:
            flash(f"Verification Failed! Only {matches} matched.", "danger")
    return render_template('forgot_password.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.phone = request.form.get('phone')
        user.address = request.form.get('address')
        user.pincode = request.form.get('pincode')
        file_to_upload = request.files.get('profile_pic')

        if file_to_upload and file_to_upload.filename != '':
            try:
                filename = secure_filename(file_to_upload.filename)
                filename = f"profile_{user.id}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_to_upload.save(file_path)

                user.profile_pic = f"/static/uploads/{filename}"
                session['user_profile_pic'] = user.profile_pic
            except Exception as e:
                flash(f"Upload error: {e}", "danger")

        db.session.commit()
        flash("Profile updated! ❤️", "success")
        return redirect(url_for('profile'))

    orders = Order.query.filter_by(user_id=user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', user=user, orders=orders)

# --- 6. Store Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/shop')
def shop():
    categories = Category.query.all()
    selected_cat = request.args.get('category')
    if selected_cat and selected_cat != 'None':
        products = Product.query.filter_by(category_id=selected_cat).all()
    else:
        products = Product.query.all()
    return render_template('shop.html', products=products, categories=categories, selected_cat=selected_cat)

@app.route('/product/<int:product_id>')
def product_view(product_id):
    product = Product.query.get_or_404(product_id)
    related = Product.query.filter(
        Product.category_id == product.category_id, 
        Product.id != product_id
    ).limit(3).all()
    return render_template('product_view.html', product=product, related=related)

# --- 7. Checkout Flow Routes ---
@app.route('/checkout/<int:product_id>')
@login_required
def checkout_page(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('checkout.html', product=product)

@app.route('/initiate_payment', methods=['POST'])
@login_required
def initiate_payment():
    try:
        data = request.get_json()
        product = Product.query.get(data.get('product_id'))
        if not product:
            return jsonify({"status": "error", "message": "Product not found"}), 404

        new_order = Order(
            user_id=session.get('user_id'),
            name=data.get('name'),
            phone=data.get('phone'),
            house_no=data.get('house'),
            address=data.get('address'),
            pincode=data.get('pincode'),
            custom_details=data.get('note'),
            delivery_mode=data.get('mode'),
            total=str(product.price),
            items=product.name,
            status="COD - Pending"
        )
        db.session.add(new_order)
        db.session.commit()

        # MongoDB Order Sync
        try:
            mg_orders.insert_one({
                'order_id': new_order.id,
                'customer_name': data.get('name'),
                'product_name': product.name,
                'amount': product.price,
                'delivery_type': data.get('mode'),
                'status': 'COD - Pending',
                'timestamp': datetime.utcnow()
            })
        except: 
            pass

        return jsonify({
            "status": "success",
            "redirect_url": url_for('thank_you', order_id=new_order.id)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/submit_order', methods=['POST'])
def submit_order():
    if 'user_id' not in session:
        return jsonify({
            "success": False,
            "message": "Order fail! Please Login or Register first to place an order."
        }), 401

    try:
        data = request.get_json()
        new_order = Order(
            user_id=session.get('user_id'),
            name=data.get('name', 'N/A'),
            phone=str(data.get('phone', 'N/A')),
            email=data.get('email'),
            house_no=data.get('house_no', 'N/A'),
            address=data.get('address', 'N/A'),
            landmark=data.get('landmark', ''),
            pincode=data.get('pincode'),
            custom_details=data.get('custom_details'),
            total=str(data.get('total', '0')),
            items=str(data.get('items', 'Unknown Item'))
        )
        db.session.add(new_order)
        db.session.commit()

        # MongoDB Order Sync
        try:
            mg_orders.insert_one({
                'order_id': new_order.id,
                'customer_name': data.get('name'),
                'items': str(data.get('items')),
                'total_amount': str(data.get('total')),
                'status': 'Pending',
                'date_ordered': datetime.utcnow()
            })
        except Exception as cloud_e:
            print(f"MongoDB Order Sync Error: {cloud_e}")

        return jsonify({"success": True, "order_id": new_order.id})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/thank_you/<int:order_id>')
@login_required
def thank_you(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('thank_you.html', order=order)

@app.route('/download_invoice/<int:order_id>')
def download_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    try:
        try:
            total_amount = float(order.total)
        except (ValueError, TypeError):
            total_amount = 0.0

        pdf = FPDF(orientation='P', unit='mm', format='A4')
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        primary_color = (255, 65, 108)
        text_dark = (44, 62, 80)
        text_light = (127, 140, 141)

        pdf.set_draw_color(*primary_color)
        pdf.set_line_width(0.5)
        pdf.rect(5, 5, 200, 287)
        pdf.set_line_width(1.5)
        pdf.rect(7, 7, 196, 283)

        pdf.ln(12)
        pdf.set_font("Helvetica", "B", 32)
        pdf.set_text_color(*primary_color)
        pdf.cell(0, 12, "HEARTSCRIPT", 0, 1, 'C')
        pdf.set_font("Helvetica", "I", 11)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 8, "Artisan Handcrafted Legacies - Shipped Globally", 0, 1, 'C')
        pdf.ln(5)

        pdf.set_fill_color(255, 245, 247)
        pdf.set_font("Times", "I", 10)
        pdf.set_text_color(60, 60, 60)
        brand_description = (
            "Welcome to HeartScript, a premier global destination where artisan craftsmanship meets deep human emotions. "
            "Our platform is dedicated to preserving your most cherished memories through meticulously handcrafted masterpieces "
            "that transcend time and borders. From bespoke love letters to personalized artistic legacies, HeartScript "
            "is recognized globally for its commitment to quality, elegance, and soul-stirring designs. Every order is "
            "a timeless heritage delivered to over 50 countries with the utmost care. Experience luxury, experience HeartScript."
        )
        pdf.set_x(15)
        pdf.multi_cell(180, 5, brand_description, 0, 'C', True)
        pdf.ln(10)

        pdf.set_draw_color(230, 230, 230)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(5)

        curr_y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*text_dark)
        pdf.set_xy(15, curr_y)
        pdf.cell(90, 6, f"ORDER ID: #HS-{order.id:05d}", 0, 1)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(90, 6, f"DATE: {order.date_ordered.strftime('%d %b, %Y')}", 0, 1)

        pdf.set_xy(110, curr_y)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(85, 6, f"STATUS: {str(order.status).upper()}", 0, 1, 'R')
        pdf.ln(8)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*primary_color)
        pdf.set_x(15)
        pdf.cell(90, 7, "BILL TO:", 0, 1)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*text_dark)
        pdf.set_x(15)
        pdf.cell(90, 6, str(order.name).upper(), 0, 1)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_x(15)
        pdf.multi_cell(90, 5, f"{order.house_no}, {order.address}, PIN: {order.pincode}")
        pdf.ln(10)

        pdf.set_x(15)
        pdf.set_fill_color(*primary_color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(130, 12, "  MASTERPIECE SELECTION", 0, 0, 'L', True)
        pdf.cell(50, 12, "TOTAL (INR)  ", 0, 1, 'R', True)

        pdf.set_x(15)
        pdf.set_fill_color(252, 252, 252)
        pdf.set_text_color(*text_dark)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(130, 15, f"  {order.items}", 'B', 0, 'L', True)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 15, f"Rs. {total_amount:,.2f}  ", 'B', 1, 'R', True)

        pdf.ln(5)
        pdf.set_x(15)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(255, 75, 43)
        pdf.cell(180, 15, f"GRAND TOTAL: Rs. {total_amount:,.2f}", 0, 1, 'R')

        pdf.set_y(-45)
        pdf.set_draw_color(*primary_color)
        pdf.line(40, pdf.get_y(), 170, pdf.get_y())
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*primary_color)
        pdf.cell(0, 5, "WWW.HEARTSCRIPT.COM", 0, 1, 'C')
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 4, "Global Luxury Gifting | Hand-Carved Memories | Secure Worldwide Shipping", 0, 1, 'C')

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            pdf.output(tmp.name)
            return send_file(tmp.name, as_attachment=True, download_name=f"HeartScript_Invoice_{order.id}.pdf")

    except Exception as e:
        print(f"Final Error: {e}")
        return f"Invoice Error: {str(e)}", 500

# --- 10. Admin Routes ---
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == 'HeartScript@Admin2025':
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        flash("Wrong Password!", "danger")
    return render_template('login.html')

@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('admin.html', orders=orders, products=products, categories=categories)

@app.route('/update_status/<int:order_id>', methods=['POST'])
def update_status(order_id):
    if not session.get('admin_logged_in'):
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    order = Order.query.get(order_id)
    new_status = request.form.get('status') or request.get_json().get('status')

    if order and new_status:
        try:
            order.status = new_status
            db.session.commit()

            # MongoDB Sync
            try:
                mg_orders.update_one({'order_id': order_id}, {'$set': {'status': new_status}})
            except Exception as cloud_e:
                print(f"MongoDB Update Warning: {cloud_e}")

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                return jsonify({"success": True, "message": "Status updated!"})

            flash(f"Order #{order_id} updated to {new_status}", "success")
            return redirect(url_for('admin'))

        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

    return jsonify({"success": False, "message": "Invalid Order"}), 400

@app.route('/add_category', methods=['POST'])
def add_category():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    name = request.form.get('name')
    if name and not Category.query.filter_by(name=name).first():
        db.session.add(Category(name=name))
        db.session.commit()
        flash("Category Added!", "success")
    return redirect(url_for('admin'))

@app.route('/add_product', methods=['POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    try:
        # Handle 3 Images
        image_urls = []
        for i in range(1, 4):
            field_name = 'product_image' if i == 1 else f'product_image{i}'
            img_file = request.files.get(field_name)
            
            if img_file and img_file.filename != '':
                original_filename = secure_filename(img_file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{i}_{original_filename}"
                img_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img_file.save(img_path)
                image_urls.append(f"/static/uploads/{filename}")
            else:
                image_urls.append("https://via.placeholder.com/300" if i==1 else "")

        new_prod = Product(
            name=request.form.get('name'),
            price=int(request.form.get('price')),
            image_url=image_urls[0],
            image_url2=image_urls[1],
            image_url3=image_urls[2],
            description=request.form.get('description'),
            category_id=int(request.form.get('category_id'))
        )
        db.session.add(new_prod)
        db.session.commit()

        # MongoDB Product Sync
        try:
            mg_products.insert_one({
                'name': request.form.get('name'), 
                'price': int(request.form.get('price')),
                'image_url1': image_urls[0], 
                'image_url2': image_urls[1], 
                'image_url3': image_urls[2], 
                'category_id': int(request.form.get('category_id')),
                'created_at': datetime.utcnow()
            })
        except Exception as cloud_e:
            print(f"MongoDB Product Sync Error: {cloud_e}")
        
        flash("Product Added Successfully! ❤️", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error: {str(e)}", "danger")
    return redirect(url_for('admin'))

@app.route('/delete_order/<int:order_id>')
def delete_order(order_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    order = Order.query.get(order_id)
    if order:
        db.session.delete(order)
        db.session.commit()
        # MongoDB Delete
        try:
            mg_orders.delete_one({'order_id': order_id})
        except Exception as e:
            print(f"MongoDB Delete Error: {e}")
        flash(f"Order #{order_id} deleted successfully!", "success")
    else:
        flash("Order not found!", "danger")
    return redirect(url_for('admin'))

@app.route('/delete_product/<int:product_id>')
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    product = Product.query.get(product_id)
    if product:
        try:
            p_name = product.name
            db.session.delete(product)
            db.session.commit()
            # MongoDB Delete
            try:
                mg_products.delete_one({'name': p_name})
            except Exception as e:
                print(f"MongoDB Product Delete Error: {e}")
            flash(f"Product '{p_name}' removed successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting product: {str(e)}", "danger")
    else:
        flash("Product not found!", "danger")
    return redirect(url_for('admin'))

@app.route('/delete_category/<int:id>')
def delete_category(id):
    if not session.get('admin_logged_in'):
        return redirect('/admin_login')
    category_to_delete = Category.query.get_or_404(id)
    try:
        products_in_cat = Product.query.filter_by(category_id=id).all()
        for p in products_in_cat:
            db.session.delete(p)
        db.session.delete(category_to_delete)
        db.session.commit()
        return redirect('/admin')
    except Exception as e:
        db.session.rollback()
        return f"Error: {str(e)}"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Railway compatibility for port
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
