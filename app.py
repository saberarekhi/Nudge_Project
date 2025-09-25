import os
import random
import csv
import io
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, g, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_babel import Babel, _
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

# --- پیکربندی اولیه اپلیکیشن ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a-very-secret-key-for-q1-research-final-version')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
basedir = os.path.abspath(os.path.dirname(__file__))
os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
os.makedirs(os.path.join(basedir, UPLOAD_FOLDER), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "project.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['BABEL_DEFAULT_LOCALE'] = 'fa'
app.config['LANGUAGES'] = {'en': 'English', 'fa': 'فارسی'}

# --- تعریف تابع انتخاب زبان ---
def get_locale():
    if 'language' in session and session['language'] in app.config['LANGUAGES']:
        return session['language']
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())

# --- مقداردهی اولیه کتابخانه‌ها ---
db = SQLAlchemy(app)
babel = Babel(app, locale_selector=get_locale)
csrf = CSRFProtect(app)

# --- میان‌افزار برای بررسی زبان قبل از هر درخواست ---
@app.before_request
def check_language():
    exempt_endpoints = ['select_language', 'set_language', 'static']
    
    if request.endpoint in exempt_endpoints:
        return
        
    if 'language' not in session:
        return redirect(url_for('select_language'))
        
    g.locale = str(get_locale())

@app.context_processor
def inject_globals():
    unread_notifications = 0
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
        if current_user:
            unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
            
    return dict(
        cache_buster=int(time.time()),
        unread_notifications=unread_notifications,
        current_user=current_user
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash("برای دسترسی به این بخش، ابتدا باید به عنوان مدیر وارد شوید.", "error")
            return redirect(url_for('admin_login'))
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            flash("شما اجازه دسترسی به این صفحه را ندارید.", "error")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- مدل‌های پایگاه داده ---
user_badges = db.Table('user_badges',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('badge_id', db.Integer, db.ForeignKey('badge.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    research_group = db.Column(db.String(1), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    email = db.Column(db.String(120), unique=True, nullable=False)
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    occupation = db.Column(db.String(50), nullable=True)
    education = db.Column(db.String(50), nullable=True)
    tech_familiarity = db.Column(db.String(20), nullable=True)
    unique_id = db.Column(db.String(20), unique=True, nullable=True)
    current_rank = db.Column(db.String(50), nullable=True)
    reports = db.relationship('Report', backref='author', lazy=True, cascade="all, delete-orphan")
    stars = db.Column(db.Integer, default=0)
    badges = db.relationship('Badge', secondary=user_badges, lazy='subquery', backref=db.backref('users', lazy=True))
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade="all, delete-orphan")
    reward_logs = db.relationship('RewardLog', backref='user', lazy=True, cascade="all, delete-orphan")
    bank_account = db.relationship('BankAccount', backref='user', uselist=False, cascade="all, delete-orphan")
    withdrawal_requests = db.relationship('WithdrawalRequest', backref='user', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='user', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password): 
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password): 
        return check_password_hash(self.password_hash, password)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_code = db.Column(db.String(30), unique=True, nullable=True)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')
    comments = db.relationship('Comment', backref='report', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='report', lazy=True, cascade="all, delete-orphan")

class RewardLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=True)
    reward_type = db.Column(db.String(10), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    report = db.relationship('Report', backref='reward_logs')

class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description_key = db.Column(db.String(200), nullable=False)
    icon = db.Column(db.String(50), nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bank_name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    sheba_number = db.Column(db.String(30), nullable=False)

class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending') # وضعیت: pending, approved, rejected
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('report_id', 'user_id', name='unique_like'),)

class Rank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    min_stars = db.Column(db.Integer, nullable=False)
    icon = db.Column(db.String(50), nullable=False)

# --- توابع کمکی ---
def create_notification(user_id, message_template, **kwargs):
    # FIX: This function now correctly handles translation for all messages.
    with app.app_context():
        message = _(message_template, **kwargs)
        new_notif = Notification(user_id=user_id, message=message)
        db.session.add(new_notif)
        db.session.commit()

def check_and_award_badges(user):
    approved_reports_count = Report.query.filter_by(user_id=user.id, status='approved').count()
    badge1 = Badge.query.filter_by(name='Top Reporter').first()
    if badge1 and approved_reports_count >= 10 and badge1 not in user.badges:
        user.badges.append(badge1)
        create_notification(user.id, "تبریک! شما نشان 'گزارشگر برتر' 🏅 را دریافت کردید!")
    
    distinct_locations_count = db.session.query(Report.latitude, Report.longitude).filter_by(user_id=user.id, status='approved').distinct().count()
    badge2 = Badge.query.filter_by(name='Neighborhood Watch').first()
    if badge2 and distinct_locations_count >= 5 and badge2 not in user.badges:
        user.badges.append(badge2)
        create_notification(user.id, "تبریک! شما نشان 'دیده‌بان محله' 🗺️ را دریافت کردید!")
    
    db.session.commit()

def generate_unique_id(user):
    return f"{user.research_group}-{user.id:03d}"

def generate_report_code(report):
    if report.author and report.author.unique_id:
        return f"{report.author.unique_id}-{report.id:04d}"
    return None

def get_user_rank(stars):
    ranks = {
        0: 'تازه کار', 10: 'مبتدی', 25: 'فعال', 50: 'حرفه‌ای', 100: 'استاد'
    }
    for threshold, rank in sorted(ranks.items(), reverse=True):
        if stars >= threshold:
            return rank
    return 'تازه کار'

def update_user_rank(user):
    rank = get_user_rank(user.stars)
    if user.current_rank != rank:
        user.current_rank = rank
        create_notification(user.id, "تبریک! شما به رتبه '%(rank)s' ارتقا یافتید! 🎉", rank=rank)
        db.session.commit()

# --- مسیرهای اپلیکیشن ---
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/select-language', methods=['GET', 'POST'])
def select_language():
    if request.method == 'POST':
        lang = request.form.get('language')
        if lang in app.config['LANGUAGES']:
            session['language'] = lang
            if 'next' in session and session['next']:
                next_page = session['next']
                session.pop('next', None)
                return redirect(next_page)
            return redirect(url_for('index'))
    
    if request.referrer and url_for('select_language') not in request.referrer:
        session['next'] = request.referrer
    
    return render_template('select_language.html')

@app.route('/language/<lang>')
def set_language(lang=None):
    if lang in app.config['LANGUAGES']:
        session['language'] = lang
    referrer = request.referrer
    if referrer:
        return redirect(referrer)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'language' not in session:
        return redirect(url_for('select_language'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        age = request.form.get('age')
        gender = request.form.get('gender')
        occupation = request.form.get('occupation')
        education = request.form.get('education')
        tech_familiarity = request.form.get('tech_familiarity')
        agreed_to_terms = request.form.get('agree_terms')
        
        if not agreed_to_terms:
            flash(_('برای ثبت‌نام باید با شرایط و قوانین موافقت کنید.'), 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash(_('نام کاربری یا ایمیل قبلاً استفاده شده است.'), 'error')
            return redirect(url_for('register'))
            
        groups = ['C', 'M', 'N', 'H']
        assigned_group = random.choice(groups)
        new_user = User(username=username, research_group=assigned_group, email=email, age=age, gender=gender, occupation=occupation, education=education, tech_familiarity=tech_familiarity)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()
        new_user.unique_id = generate_unique_id(new_user)
        db.session.commit()
        
        flash(_('ثبت‌نام با موفقیت انجام شد! اکنون می‌توانید وارد شوید.'), 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'language' not in session:
        return redirect(url_for('select_language'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash(_('نام کاربری یا رمز عبور اشتباه است.'), 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = (user.role == 'admin')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash(_('نام کاربری یا رمز عبور اشتباه است.'), 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    total_reports = Report.query.filter_by(user_id=user.id).count()
    approved_reports = Report.query.filter_by(user_id=user.id, status='approved').count()
    success_rate = (approved_reports / total_reports * 100) if total_reports > 0 else 0
    stats = {'total': total_reports, 'approved': approved_reports, 'rate': round(success_rate, 1)}
    
    if request.method == 'POST':
        description = request.form['description']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        image_file = request.files.get('image')
        filename = None
        
        if image_file:
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user.id))
            os.makedirs(user_upload_dir, exist_ok=True)
            
            if not allowed_file(image_file.filename):
                flash(_('تنها فایل‌های تصویری مجاز هستند.'), 'error')
                return redirect(request.url)
            file_ext = image_file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(image_file.filename)
            filename = f"report_{user.id}_{int(time.time())}.{file_ext}"
            image_file.save(os.path.join(user_upload_dir, filename))
            
        new_report = Report(description=description, author=user, image_filename=filename, 
                           latitude=latitude if latitude else None, longitude=longitude if longitude else None)
        db.session.add(new_report)
        db.session.flush()

        new_report.report_code = generate_report_code(new_report)

        db.session.commit()
        
        admins = User.query.filter_by(role='admin').all()
        for admin in admins:
            create_notification(admin.id, "گزارش جدیدی توسط کاربر '%(username)s' ثبت شد. لطفاً بررسی کنید.", username=user.username)

        flash(_('گزارش شما با موفقیت ثبت شد و در حال بررسی است.'), 'success')
        return redirect(url_for('dashboard'))
        
    user_reports = Report.query.filter_by(user_id=user.id).order_by(Report.timestamp.desc()).limit(10).all()
    recent_reports = Report.query.filter_by(status='approved').order_by(Report.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', user=user, reports=user_reports, recent_reports=recent_reports, stats=stats)

@app.route('/logout')
def logout():
    language = session.get('language')
    session.clear()
    if language:
        session['language'] = language
    flash(_('شما با موفقیت از حساب خود خارج شدید.'), 'success')
    return redirect(url_for('login'))

@app.route('/terms')
def terms():
    if 'language' not in session:
        return redirect(url_for('select_language'))
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    if 'language' not in session:
        return redirect(url_for('select_language'))
    return render_template('privacy.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    user = User.query.get_or_404(session['user_id'])
    total_reports = Report.query.filter_by(user_id=user.id).count()
    approved_reports = Report.query.filter_by(user_id=user.id, status='approved').count()
    success_rate = (approved_reports / total_reports * 100) if total_reports > 0 else 0
    reward_history = RewardLog.query.filter_by(user_id=user.id).order_by(RewardLog.timestamp.desc()).all()
    stats = {'total': total_reports, 'approved': approved_reports, 'rate': round(success_rate, 1)}
    
    return render_template('profile.html', user=user, stats=stats, history=reward_history)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        user.age = request.form.get('age')
        user.gender = request.form.get('gender')
        user.occupation = request.form.get('occupation')
        user.education = request.form.get('education')
        user.tech_familiarity = request.form.get('tech_familiarity')
        db.session.commit()
        flash(_('پروفایل شما با موفقیت به‌روزرسانی شد.'), 'success')
        return redirect(url_for('profile'))
        
    return render_template('edit_profile.html', user=user)

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    if user.research_group not in ['N', 'H']:
        flash(_('این بخش برای گروه شما فعال نیست.'), 'warning')
        return redirect(url_for('dashboard'))
        
    today = datetime.utcnow().date()
    start_of_week = today - timedelta(days=today.weekday())
    top_users = db.session.query(User, func.count(Report.id).label('approved_count')).join(Report).filter(
        User.research_group.in_(['N', 'H']), Report.status == 'approved', Report.timestamp >= start_of_week
    ).group_by(User.id).order_by(func.count(Report.id).desc()).limit(10).all()
    
    user_rank_query = db.session.query(User.id, func.count(Report.id).label('approved_count')).join(Report).filter(
        User.research_group.in_(['N', 'H']), Report.status == 'approved', Report.timestamp >= start_of_week
    ).group_by(User.id).order_by(func.count(Report.id).desc()).all()
    
    rank = 0
    for i, (u_id, count) in enumerate(user_rank_query):
        if u_id == user.id:
            rank = i + 1
            break
            
    return render_template('leaderboard.html', top_users=top_users, user_rank=rank)

@app.route('/notifications')
def notifications():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    user_notifications = Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.timestamp.desc()).all()
    Notification.query.filter_by(user_id=session['user_id'], is_read=False).update({'is_read': True})
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/uploads/<int:user_id>/<filename>')
def uploaded_file(user_id, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], str(user_id)), filename)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash("لطفاً نام کاربری و رمز عبور را وارد کنید.", "error")
            return render_template('admin_login.html')
            
        user = User.query.filter_by(username=username, role='admin').first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = True
            flash("با موفقیت وارد شدید.", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("نام کاربری یا رمز عبور ادمین اشتباه است.", "error")
    
    return render_template('admin_login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    filters = {
        'user_search': request.args.get('user_search', ''),
        'user_group': request.args.get('user_group', ''),
        'report_search': request.args.get('report_search', ''),
        'report_status': request.args.get('report_status', ''),
        'report_group': request.args.get('report_group', ''),
        'start_date': request.args.get('start_date', ''),
        'end_date': request.args.get('end_date', '')
    }
    
    users_query = User.query.filter_by(role='user')
    if filters['user_search']: 
        users_query = users_query.filter(User.username.ilike(f"%{filters['user_search']}%"))
    if filters['user_group']: 
        users_query = users_query.filter_by(research_group=filters['user_group'])
    filtered_users = users_query.order_by(User.id.desc()).all()
    
    reports_query = Report.query.join(User)
    if filters['report_search']: 
        reports_query = reports_query.filter(Report.description.ilike(f"%{filters['report_search']}%"))
    if filters['report_status']: 
        reports_query = reports_query.filter(Report.status == filters['report_status'])
    if filters['report_group']: 
        reports_query = reports_query.filter(User.research_group == filters['report_group'])
    if filters['start_date']:
        start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
        reports_query = reports_query.filter(Report.timestamp >= start_date)
    if filters['end_date']:
        end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d') + timedelta(days=1)
        reports_query = reports_query.filter(Report.timestamp < end_date)
        
    filtered_reports = reports_query.order_by(Report.timestamp.desc()).all()
    
    pending_withdrawals = WithdrawalRequest.query.filter_by(status='pending').order_by(WithdrawalRequest.timestamp.asc()).all()
    
    total_users = User.query.filter_by(role='user').count()
    total_reports = Report.query.count()
    approved_reports_count = Report.query.filter_by(status='approved').count()
    approval_rate = (approved_reports_count / total_reports * 100) if total_reports > 0 else 0
    avg_reports_per_user = total_reports / total_users if total_users > 0 else 0
    
    stats = {
        "total_users": total_users,
        "total_reports": total_reports,
        "approval_rate": round(approval_rate, 1),
        "avg_reports": round(avg_reports_per_user, 2)
    }
    
    user_dist_query = db.session.query(User.research_group, func.count(User.id)).filter(User.role == 'user').group_by(User.research_group).all()
    pie_chart_data = {"labels": [item[0] for item in user_dist_query], "data": [item[1] for item in user_dist_query]}
    
    seven_days_ago = datetime.utcnow() - timedelta(days=6)
    reports_per_day_query = db.session.query(func.strftime('%Y-%m-%d', Report.timestamp), func.count(Report.id)).filter(
        Report.timestamp >= seven_days_ago.date()).group_by(func.strftime('%Y-%m-%d', Report.timestamp)
    ).order_by(func.strftime('%Y-%m-%d', Report.timestamp)).all()
    
    bar_chart_labels = [(seven_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
    bar_chart_data_map = {item[0]: item[1] for item in reports_per_day_query}
    bar_chart_data = [bar_chart_data_map.get(label, 0) for label in bar_chart_labels]
    bar_chart = {"labels": bar_chart_labels, "data": bar_chart_data}
    
    heatmap_points = db.session.query(Report.latitude, Report.longitude).filter(
        Report.latitude.isnot(None), Report.longitude.isnot(None)).all()
    heatmap_data = [[point.latitude, point.longitude] for point in heatmap_points]
    
    return render_template('admin.html', users=filtered_users, reports=filtered_reports, stats=stats, 
                         pie_chart_data=pie_chart_data, bar_chart=bar_chart, filters=filters, heatmap_data=heatmap_data,
                         pending_withdrawals=pending_withdrawals)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    user = User.query.get_or_404(user_id)
    user_reports = Report.query.filter_by(user_id=user.id).order_by(Report.timestamp.desc()).all()
    return render_template('admin_user_profile.html', user=user, reports=user_reports)

@app.route('/admin/report/<int:report_id>')
@admin_required
def admin_view_report(report_id):
    report = Report.query.get_or_404(report_id)
    return render_template('admin_report.html', report=report)

@app.route('/admin/user/<int:user_id>/send_message', methods=['POST'])
@admin_required
def admin_send_direct_message(user_id):
    user = User.query.get_or_404(user_id)
    message_text = request.form.get('message_text')
    
    if message_text:
        create_notification(user.id, message_text)
        flash(f"پیام شما با موفقیت برای {user.username} ارسال شد.", "success")
    else:
        flash("متن پیام نمی‌تواند خالی باشد.", "error")
        
    return redirect(url_for('admin_view_user', user_id=user_id))

@app.route('/admin/send_message', methods=['POST'])
@admin_required
def admin_send_message():
    target_group = request.form.get('target_group')
    message_text = request.form.get('message_text')
    
    if not target_group or not message_text:
        flash("لطفاً گروه و متن پیام را مشخص کنید.", "error")
        return redirect(url_for('admin_dashboard'))
        
    if target_group == 'all':
        users_to_notify = User.query.filter_by(role='user').all()
    else:
        users_to_notify = User.query.filter_by(research_group=target_group, role='user').all()
        
    for user in users_to_notify:
        create_notification(user.id, message_text)
        
    flash(f"پیام شما با موفقیت برای {len(users_to_notify)} کاربر ارسال شد.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/review_report/<int:report_id>/<action>')
@admin_required
def review_report(report_id, action):
    report = Report.query.get_or_404(report_id)
    user = report.author
    
    if report.status == 'pending':
        if action == 'approve':
            report.status = 'approved'
            create_notification(user.id, "گزارش شما با شناسه %(report_id)s تایید شد. از مشارکت شما متشکریم!", report_id=report.id)
            
            if user.research_group in ['M', 'H']:
                amount = 10000
                user.balance += amount
                log = RewardLog(user_id=user.id, report_id=report.id, reward_type='balance', amount=amount)
                db.session.add(log)
                
            if user.research_group in ['N', 'H']:
                amount = 10
                user.stars += amount
                log = RewardLog(user_id=user.id, report_id=report.id, reward_type='stars', amount=amount)
                db.session.add(log)
                update_user_rank(user)
                
            check_and_award_badges(user)
            
        elif action == 'reject':
            report.status = 'rejected'
            create_notification(user.id, "گزارش شما با شناسه %(report_id)s رد شد. لطفاً در ثبت گزارش‌های بعدی دقت فرمایید.", report_id=report.id)
            
        db.session.commit()
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/withdrawal/<int:request_id>/<action>')
@admin_required
def admin_review_withdrawal(request_id, action):
    req = WithdrawalRequest.query.get_or_404(request_id)
    user = req.user
    
    if req.status == 'pending':
        if action == 'approve':
            req.status = 'approved'
            create_notification(user.id, "درخواست برداشت وجه شما به مبلغ %(amount)s تومان تایید و پرداخت شد.", amount=f"{req.amount:,.0f}")
            flash(_('درخواست برداشت با موفقیت تایید شد.'), 'success')
            
        elif action == 'reject':
            req.status = 'rejected'
            user.balance += req.amount
            create_notification(user.id, "درخواست برداشت وجه شما به مبلغ %(amount)s تومان رد شد. مبلغ به حساب شما بازگردانده شد.", amount=f"{req.amount:,.0f}")
            flash(_('درخواست برداشت رد شد و مبلغ به کاربر بازگردانده شد.'), 'info')
            
        db.session.commit()
    else:
        flash(_('این درخواست قبلاً بررسی شده است.'), 'warning')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/run_smart_nudge', methods=['POST'])
@admin_required
def run_smart_nudge():
    users_to_nudge = User.query.filter(User.research_group.in_(['N', 'H'])).all()
    notifications_sent = 0
    
    for user in users_to_nudge:
        last_report = Report.query.filter_by(user_id=user.id).order_by(Report.timestamp.desc()).first()
        
        if last_report and last_report.timestamp < datetime.utcnow() - timedelta(days=3):
            recent_inactivity_notif = Notification.query.filter(
                Notification.user_id == user.id, 
                Notification.message.like('%منتظر مشارکت شما هستیم%'), 
                Notification.timestamp > datetime.utcnow() - timedelta(days=1)
            ).first()
            
            if not recent_inactivity_notif:
                create_notification(user.id, "ما ۳ روز است که منتظر مشارکت شما هستیم! به ما در بهبود شهر کمک کنید.")
                notifications_sent += 1
                
        approved_reports_count = Report.query.filter_by(user_id=user.id, status='approved').count()
        badge1 = Badge.query.filter_by(name='Top Reporter').first()
        
        if badge1 and approved_reports_count == 9 and badge1 not in user.badges:
            create_notification(user.id, "شما فقط ۱ گزارش دیگر تا گرفتن نشان 'گزارشگر برتر' فاصله دارید! به تلاشتان ادامه دهید.")
            notifications_sent += 1
            
    flash(f"{notifications_sent} نوتیفیکیشن هوشمند با موفقیت برای کاربران ارسال شد.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/export/users')
@admin_required
def export_users_csv():
    users = User.query.filter_by(role='user').all()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['user_id', 'unique_id', 'username', 'email', 'age', 'gender', 'occupation', 'education', 'tech_familiarity', 'research_group', 'balance', 'stars', 'current_rank']
    writer.writerow(header)
    
    for user in users:
        row = [user.id, user.unique_id, user.username, user.email, user.age, user.gender, 
               user.occupation, user.education, user.tech_familiarity, user.research_group, user.balance, user.stars, user.current_rank]
        writer.writerow(row)
        
    output.seek(0)
    return Response(output.getvalue().encode('utf-8'), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=users_export.csv"})

@app.route('/export/reports')
@admin_required
def export_reports_csv():
    reports = Report.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['report_id', 'user_id', 'user_unique_id', 'user_group', 'description', 'latitude', 'longitude', 'image_filename', 'timestamp', 'status']
    writer.writerow(header)
    
    for report in reports:
        row = [report.id, report.author.id, report.author.unique_id, report.author.research_group, 
               report.description, report.latitude, report.longitude, report.image_filename, 
               report.timestamp.strftime('%Y-%m-%d %H:%M:%S'), report.status]
        writer.writerow(row)
        
    output.seek(0)
    return Response(output.getvalue().encode('utf-8'), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=reports_export.csv"})

@app.route('/export/comments')
@admin_required
def export_comments_csv():
    comments = Comment.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['comment_id', 'report_id', 'user_id', 'user_unique_id', 'text', 'timestamp']
    writer.writerow(header)
    
    for comment in comments:
        row = [comment.id, comment.report_id, comment.user_id, comment.user.unique_id, 
               comment.text, comment.timestamp.strftime('%Y-%m-%d %H:%M:%S')]
        writer.writerow(row)
        
    output.seek(0)
    return Response(output.getvalue().encode('utf-8'), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=comments_export.csv"})

@app.route('/export/likes')
@admin_required
def export_likes_csv():
    likes = Like.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['like_id', 'report_id', 'user_id', 'user_unique_id', 'timestamp']
    writer.writerow(header)
    
    for like in likes:
        row = [like.id, like.report_id, like.user_id, like.user.unique_id, like.timestamp.strftime('%Y-%m-%d %H:%M:%S')]
        writer.writerow(row)
        
    output.seek(0)
    return Response(output.getvalue().encode('utf-8'), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=likes_export.csv"})

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.research_group not in ['M', 'H']:
        flash(_('این قابلیت برای گروه شما فعال نیست'), 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
        except (ValueError, TypeError):
            flash(_('لطفاً مبلغ معتبری وارد کنید.'), 'error')
            return redirect(url_for('withdraw'))
            
        if amount < 10000:
            flash(_('حداقل مبلغ قابل برداشت ۱۰,۰۰۰ تومان است.'), 'error')
            return redirect(url_for('withdraw'))
            
        if amount > user.balance:
            flash(_('موجودی کافی نیست'), 'error')
            return redirect(url_for('withdraw'))
        
        user.balance -= amount
        withdrawal = WithdrawalRequest(user_id=user.id, amount=amount)
        db.session.add(withdrawal)
        db.session.commit()
        
        flash(_('درخواست برداشت شما ثبت شد'), 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('withdraw.html', user=user)

@app.route('/bank_account', methods=['GET', 'POST'])
def bank_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        bank_name = request.form['bank_name']
        account_number = request.form['account_number']
        sheba_number = request.form['sheba_number']
        
        if user.bank_account:
            user.bank_account.bank_name = bank_name
            user.bank_account.account_number = account_number
            user.bank_account.sheba_number = sheba_number
        else:
            bank_account = BankAccount(
                user_id=user.id,
                bank_name=bank_name,
                account_number=account_number,
                sheba_number=sheba_number
            )
            db.session.add(bank_account)
        
        db.session.commit()
        flash(_('اطلاعات حساب بانکی با موفقیت ذخیره شد'), 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('bank_account.html', user=user)

@app.route('/like_report/<int:report_id>')
def like_report(report_id):
    if 'user_id' not in session:
        return jsonify({'error': _('لطفاً ابتدا وارد شوید')}), 401
    
    report = Report.query.get_or_404(report_id)
    user_id = session['user_id']
    
    existing_like = Like.query.filter_by(report_id=report_id, user_id=user_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'liked': False, 'likes': Like.query.filter_by(report_id=report_id).count()})
    else:
        new_like = Like(report_id=report_id, user_id=user_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'liked': True, 'likes': Like.query.filter_by(report_id=report_id).count()})

@app.route('/comment_report/<int:report_id>', methods=['POST'])
def comment_report(report_id):
    if 'user_id' not in session:
        flash(_('لطفاً ابتدا وارد شوید'), 'error')
        return redirect(url_for('login'))
    
    text = request.form.get('comment_text', '').strip()
    if not text:
        flash(_('لطفاً متن کامنت را وارد کنید'), 'error')
        return redirect(request.referrer or url_for('dashboard'))
    
    new_comment = Comment(
        report_id=report_id,
        user_id=session['user_id'],
        text=text
    )
    db.session.add(new_comment)
    db.session.commit()
    
    flash(_('کامنت شما با موفقیت ثبت شد'), 'success')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/top_reports')
def top_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    top_liked = db.session.query(
        Report, 
        func.count(Like.id).label('likes_count')
    ).outerjoin(Like).group_by(Report.id).order_by(func.count(Like.id).desc()).limit(10).all()
    
    top_commented = db.session.query(
        Report, 
        func.count(Comment.id).label('comments_count')
    ).outerjoin(Comment).group_by(Report.id).order_by(func.count(Comment.id).desc()).limit(10).all()
    
    return render_template('top_reports.html', 
                         top_liked=top_liked, 
                         top_commented=top_commented)

@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    
    if Badge.query.count() == 0:
        badge1 = Badge(name='Top Reporter', description_key='Achieved for 10 approved reports', icon='🏅')
        badge2 = Badge(name='Neighborhood Watch', description_key='Achieved for reporting in 5 distinct locations', icon='🗺️')
        db.session.add_all([badge1, badge2])
    
    if Rank.query.count() == 0:
        ranks = [
            Rank(name='تازه کار', min_stars=0, icon='🌟'),
            Rank(name='مبتدی', min_stars=10, icon='⭐⭐'),
            Rank(name='فعال', min_stars=25, icon='⭐⭐⭐'),
            Rank(name='حرفه‌ای', min_stars=50, icon='⭐⭐⭐⭐'),
            Rank(name='استاد', min_stars=100, icon='⭐⭐⭐⭐⭐')
        ]
        db.session.add_all(ranks)
    
    db.session.commit()
    print("پایگاه داده با موفقیت ایجاد شد.")

@app.cli.command("create-admin")
def create_admin():
    username = input("نام کاربری ادمین را وارد کنید: ")
    email = input("ایمیل ادمین را وارد کنید: ")
    password = input("رمز عبور ادمین را وارد کنید: ")
    
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        print("خطا: این نام کاربری یا ایمیل قبلاً وجود دارد.")
        return
        
    admin_user = User(username=username, email=email, role='admin', research_group='A')
    admin_user.set_password(password)
    admin_user.unique_id = "ADMIN"
    db.session.add(admin_user)
    db.session.commit()
    
    print(f"کاربر ادمین '{username}' با موفقیت ایجاد شد.")

@app.cli.command("delete-user")
def delete_user():
    username = input("نام کاربری مورد نظر برای حذف را وارد کنید: ")
    user = User.query.filter_by(username=username).first()
    
    if user:
        if user.role == 'admin':
            print(f"امکان حذف کاربر ادمین از این طریق وجود ندارد.")
            return
            
        user.badges.clear()
        RewardLog.query.filter_by(user_id=user.id).delete()
        Notification.query.filter_by(user_id=user.id).delete()
        Report.query.filter_by(user_id=user.id).delete()
        Comment.query.filter_by(user_id=user.id).delete()
        Like.query.filter_by(user_id=user.id).delete()
        if user.bank_account:
            db.session.delete(user.bank_account)
        WithdrawalRequest.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        
        print(f"کاربر '{username}' و تمام داده‌های مرتبط با او با موفقیت حذف شدند.")
    else:
        print(f"خطا: کاربری با نام '{username}' پیدا نشد.")
@app.cli.command("backfill-report-codes")
def backfill_report_codes_command():
    """Generates unique codes for existing reports that don't have one."""
    # FIX: All of the following code is now correctly indented inside the function.
    with app.app_context():
        reports_to_update = Report.query.filter(Report.report_code.is_(None)).all()
        
        if not reports_to_update:
            print("All reports already have a code.")
            return # FIX: The incorrect 'return new_func()' is replaced with a simple 'return'.

        count = 0
        for report in reports_to_update:
            report.report_code = generate_report_code(report)
            count += 1
        
        db.session.commit()
        print(f"Successfully generated codes for {count} existing reports.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if Badge.query.count() == 0:
            badge1 = Badge(name='Top Reporter', description_key='Achieved for 10 approved reports', icon='🏅')
            badge2 = Badge(name='Neighborhood Watch', description_key='Achieved for reporting in 5 distinct locations', icon='🗺️')
            db.session.add_all([badge1, badge2])
        if Rank.query.count() == 0:
            ranks = [
                Rank(name='تازه کار', min_stars=0, icon='🌟'),
                Rank(name='مبتدی', min_stars=10, icon='⭐⭐'),
                Rank(name='فعال', min_stars=25, icon='⭐⭐⭐'),
                Rank(name='حرفه‌ای', min_stars=50, icon='⭐⭐⭐⭐'),
                Rank(name='استاد', min_stars=100, icon='⭐⭐⭐⭐⭐')
            ]
            db.session.add_all(ranks)
        db.session.commit()
        
    app.run(debug=True, port=5001)

def new_func():
    return