import os
import io
import tempfile
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

# MongoDB and BSON for ID handling
from pymongo import MongoClient
from bson.objectid import ObjectId

from flask import (
    Flask, render_template, request, jsonify, 
    flash, redirect, url_for, session, send_file
)
from flask_cors import CORS
from werkzeug.utils import secure_filename
# Note: werkzeug.security is used for hashing and checking passwords
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# --- 1. Basic Configuration ---
app.config['SECRET_KEY'] = 'HeartScript_Secret_Admin_2025_Key'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- 2. MongoDB Atlas Setup (Full & Final Fix) ---
# RFC 3986 encoding for special characters like '@' in password
m_user = urllib.parse.quote_plus('heartscript025_db_user')
m_pass = urllib.parse.quote_plus('HeartScript@Admin2025')
MONGO_URI = f"mongodb+srv://{m_user}:{m_pass}@heartscript.secaej6.mongodb.net/?retryWrites=true&w=majority&appName=HeartScript"

# Initialize MongoDB Client
client = MongoClient(MONGO_URI)
m_db = client.heartscript_db 
mg_users = m_db.users
mg_products = m_db.products
mg_orders = m_db.orders
mg_categories = m_db.categories

# Connection Test for Logs
try:
    client.admin.command('ping')
    print("✅ MongoDB Atlas Connected Successfully!")
except Exception as e:
    print(f"⚠️ MongoDB Connection Error: {e}")

# --- 3. Auth Decorators & Helper Functions ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to proceed.", "info")
            return redirect(url_for('user_login'))
        
        user = mg_users.find_one({"_id": ObjectId(session['user_id'])})
        if not user:
            session.clear()
            flash("Account error. Please login again.", "danger")
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- 4. User Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        if mg_users.find_one({"email": email}):
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(request.form.get('password'))

        user_data = {
            'username': request.form.get('username'),
            'email': email,
            'password_hash': hashed_pw,
            'phone': request.form.get('phone'),
            'address': request.form.get('address'),
            'pincode': request.form.get('pincode'),
            'role': 'customer',
            'ans1': request.form.get('ans1', '').strip().lower(),
            'ans2': request.form.get('ans2', '').strip().lower(),
            'ans3': request.form.get('ans3', '').strip().lower(),
            'ans4': request.form.get('ans4', '').strip().lower(),
            'ans5': request.form.get('ans5', '').strip().lower(),
            'ans6': request.form.get('ans6', '').strip().lower(),
            'ans7': request.form.get('ans7', '').strip().lower(),
            'profile_pic': "/static/uploads/default_avatar.png",
            'created_at': datetime.utcnow()
        }

        ans_keys = ['ans1', 'ans2', 'ans3', 'ans4', 'ans5', 'ans6', 'ans7']
        filled_count = sum(1 for k in ans_keys if user_data[k] != '')
        
        if filled_count < 3:
            flash("Please answer at least 3 security questions!", "warning")
            return redirect(url_for('register'))

        mg_users.insert_one(user_data)
        flash("Account created! Welcome to HeartScript.", "success")
        return redirect(url_for('user_login'))
        
    return render_template('register.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = mg_users.find_one({"email": email})
        
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = str(user['_id'])
            session['user_name'] = user['username']
            session['user_email'] = user['email']
            session['user_profile_pic'] = user.get('profile_pic', "/static/uploads/default_avatar.png")
            return redirect(url_for('home'))
            
        flash("Invalid email or password.", "danger")
    return render_template('user_login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = mg_users.find_one({"email": email})
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for('forgot_password'))

        matches = 0
        for i in range(1, 8):
            provided = request.form.get(f'ans{i}', '').strip().lower()
            stored = user.get(f'ans{i}', '')
            if provided and stored and provided == stored:
                matches += 1

        if matches >= 3:
            new_password = request.form.get('new_password')
            new_hash = generate_password_hash(new_password)
            mg_users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})
            flash("Success! Password updated.", "success")
            return redirect(url_for('user_login'))
        else:
            flash(f"Verification Failed! Only {matches} matched.", "danger")
            
    return render_template('forgot_password.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = mg_users.find_one({"_id": ObjectId(session['user_id'])})
    if request.method == 'POST':
        update_data = {
            "phone": request.form.get('phone'),
            "address": request.form.get('address'),
            "pincode": request.form.get('pincode')
        }
        file_to_upload = request.files.get('profile_pic')
        if file_to_upload and file_to_upload.filename != '':
            try:
                filename = secure_filename(file_to_upload.filename)
                filename = f"profile_{session['user_id']}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_to_upload.save(file_path)
                update_data["profile_pic"] = f"/static/uploads/{filename}"
                session['user_profile_pic'] = update_data["profile_pic"]
            except Exception as e:
                flash(f"Upload error: {e}", "danger")

        mg_users.update_one({"_id": user["_id"]}, {"$set": update_data})
        flash("Profile updated! ❤️", "success")
        return redirect(url_for('profile'))

    orders = list(mg_orders.find({"user_id": session['user_id']}).sort("date_ordered", -1))
    return render_template('profile.html', user=user, orders=orders)

# --- 5. Store Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/shop')
def shop():
    categories = list(mg_categories.find())
    selected_cat = request.args.get('category')
    if selected_cat and selected_cat != 'None':
        products = list(mg_products.find({"category_id": selected_cat}))
    else:
        products = list(mg_products.find())
    return render_template('shop.html', products=products, categories=categories, selected_cat=selected_cat)

@app.route('/product/<product_id>')
def product_view(product_id):
    product = mg_products.find_one({"_id": ObjectId(product_id)})
    if not product:
        return "Product Not Found", 404
    related = list(mg_products.find({
        "category_id": product.get("category_id"),
        "_id": {"$ne": ObjectId(product_id)}
    }).limit(3))
    return render_template('product_view.html', product=product, related=related)

# --- 6. Checkout & Order Management ---

@app.route('/checkout/<string:product_id>')
@login_required
def checkout_page(product_id):
    try:
        # 1. Product fetch karein
        product = mg_products.find_one({"_id": ObjectId(product_id)})
        
        if not product:
            flash("Product nahi mila!", "danger")
            return redirect(url_for('home')) # FIXED: 'index' to 'home'

        # 2. Categories fetch karein
        # FIXED: 'db.categories' to 'mg_categories'
        all_categories = list(mg_categories.find())

        # 3. Checkout template par product aur categories dono bhejein
        return render_template('checkout.html', 
                               product=product, 
                               categories=all_categories)
                               
    except Exception as e:
        print(f"Checkout Error: {e}")
        flash("Kuch galti hui, kripya dubara koshish karein.", "danger")
        return redirect(url_for('home')) # FIXED: 'index' to 'home'

@app.route('/initiate_payment', methods=['POST'])
@login_required
def initiate_payment():
    try:
        data = request.get_json()
        product = mg_products.find_one({"_id": ObjectId(data.get('product_id'))})
        if not product:
            return jsonify({"status": "error", "message": "Product not found"}), 404

        order_data = {
            "user_id": session.get('user_id'),
            "name": data.get('name'),
            "phone": data.get('phone'),
            "house_no": data.get('house'),
            "address": data.get('address'),
            "pincode": data.get('pincode'),
            "custom_details": data.get('note'),
            "delivery_mode": data.get('mode'),
            "total": str(product['price']),
            "items": product['name'],
            "status": "COD - Pending",
            "date_ordered": datetime.utcnow()
        }
        result = mg_orders.insert_one(order_data)
        return jsonify({
            "status": "success",
            "redirect_url": url_for('thank_you', order_id=str(result.inserted_id))
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/submit_order', methods=['POST'])
def submit_order():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Order fail! Please Login or Register first."}), 401
    try:
        data = request.get_json()
        order_data = {
            "user_id": session.get('user_id'),
            "name": data.get('name', 'N/A'),
            "phone": str(data.get('phone', 'N/A')),
            "email": data.get('email'),
            "house_no": data.get('house_no', 'N/A'),
            "address": data.get('address', 'N/A'),
            "landmark": data.get('landmark', ''),
            "pincode": data.get('pincode'),
            "custom_details": data.get('custom_details'),
            "total": str(data.get('total', '0')),
            "items": str(data.get('items', 'Unknown Item')),
            "status": "Pending",
            "date_ordered": datetime.utcnow()
        }
        result = mg_orders.insert_one(order_data)
        return jsonify({"success": True, "order_id": str(result.inserted_id)})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/thank_you/<order_id>')
@login_required
def thank_you(order_id):
    order = mg_orders.find_one({"_id": ObjectId(order_id)})
    if not order:
        return "Order Not Found", 404
    return render_template('thank_you.html', order=order)

@app.route('/download_invoice/<order_id>')
def download_invoice(order_id):
    order = mg_orders.find_one({"_id": ObjectId(order_id)})
    if not order:
        return "Order Not Found", 404
    try:
        try:
            total_amount = float(order.get('total', 0))
        except:
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
            "Every order is a timeless heritage delivered to over 50 countries with the utmost care."
        )
        pdf.set_x(15)
        pdf.multi_cell(180, 5, brand_description, 0, 'C', True)
        pdf.ln(10)

        curr_y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*text_dark)
        pdf.set_xy(15, curr_y)
        pdf.cell(90, 6, f"ORDER ID: #HS-{str(order['_id'])[:8].upper()}", 0, 1)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(90, 6, f"DATE: {order['date_ordered'].strftime('%d %b, %Y')}", 0, 1)

        pdf.set_xy(110, curr_y)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(85, 6, f"STATUS: {str(order['status']).upper()}", 0, 1, 'R')
        pdf.ln(8)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*primary_color)
        pdf.set_x(15)
        pdf.cell(90, 7, "BILL TO:", 0, 1)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*text_dark)
        pdf.set_x(15)
        pdf.cell(90, 6, str(order['name']).upper(), 0, 1)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_x(15)
        pdf.multi_cell(90, 5, f"{order.get('house_no', '')}, {order.get('address', '')}, PIN: {order.get('pincode', '')}")
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
        pdf.cell(130, 15, f"  {order['items']}", 'B', 0, 'L', True)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 15, f"Rs. {total_amount:,.2f}  ", 'B', 1, 'R', True)

        pdf.ln(5)
        pdf.set_x(15)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(255, 75, 43)
        pdf.cell(180, 15, f"GRAND TOTAL: Rs. {total_amount:,.2f}", 0, 1, 'R')

        pdf.set_y(-45)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*primary_color)
        pdf.cell(0, 5, "WWW.HEARTSCRIPT.COM", 0, 1, 'C')

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            pdf.output(tmp.name)
            return send_file(tmp.name, as_attachment=True, download_name=f"HeartScript_Invoice.pdf")

    except Exception as e:
        return f"Invoice Error: {str(e)}", 500

# --- 7. Admin Routes ---

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
    orders = list(mg_orders.find().sort("date_ordered", -1))
    products = list(mg_products.find())
    categories = list(mg_categories.find())
    return render_template('admin.html', orders=orders, products=products, categories=categories)

@app.route('/update_status/<order_id>', methods=['POST'])
def update_status(order_id):
    if not session.get('admin_logged_in'):
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    new_status = request.form.get('status') or request.get_json().get('status')
    if new_status:
        mg_orders.update_one({"_id": ObjectId(order_id)}, {"$set": {"status": new_status}})
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({"success": True, "message": "Status updated!"})
        flash(f"Order updated to {new_status}", "success")
        return redirect(url_for('admin'))
    return jsonify({"success": False, "message": "Invalid status"}), 400

@app.route('/add_category', methods=['POST'])
def add_category():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    name = request.form.get('name')
    if name and not mg_categories.find_one({"name": name}):
        mg_categories.insert_one({"name": name})
        flash("Category Added!", "success")
    return redirect(url_for('admin'))

@app.route('/add_product', methods=['POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    try:
        image_urls = []
        for i in range(1, 4):
            field_name = f'product_image{i}'
            img_file = request.files.get(field_name)
            
            manual_url = request.form.get(f'manual_image_url{i}')

            if img_file and img_file.filename != '':
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{i}_{secure_filename(img_file.filename)}"
                img_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img_file.save(img_path)
                image_urls.append(filename) 
            elif manual_url:
                image_urls.append(manual_url)
            else:
                image_urls.append("")

        product_data = {
            "name": request.form.get('name'),
            "price": int(request.form.get('price')),
            "image_url": image_urls[0],
            "image_url2": image_urls[1],
            "image_url3": image_urls[2],
            "description": request.form.get('description'),
            "category_id": request.form.get('category_id'),
            "created_at": datetime.utcnow()
        }
        mg_products.insert_one(product_data)
        flash("Product Added Successfully! ❤️", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
    return redirect(url_for('admin'))

@app.route('/delete_order/<order_id>')
def delete_order(order_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    mg_orders.delete_one({"_id": ObjectId(order_id)})
    flash("Order deleted successfully!", "success")
    return redirect(url_for('admin'))

@app.route('/delete_product/<product_id>')
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    mg_products.delete_one({"_id": ObjectId(product_id)})
    flash("Product removed successfully!", "success")
    return redirect(url_for('admin'))

@app.route('/delete_category/<cat_id>')
def delete_category(cat_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    mg_products.delete_many({"category_id": cat_id})
    mg_categories.delete_one({"_id": ObjectId(cat_id)})
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
