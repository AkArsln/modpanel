from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from datetime import datetime, timedelta
import requests
from flask import session
from bs4 import BeautifulSoup
import re
from urllib.parse import parse_qs, urlparse, parse_qsl
from sqlalchemy import desc
import json
import schedule
import threading
import time
from zoneinfo import ZoneInfo
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import shutil
import logging
from datetime import datetime as dt
from flask_migrate import Migrate

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# PostgreSQL URL'sini düzelt
database_url = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

# Proje modeli
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # Momaily, Liebesfun, Beloops
    description = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)

# Günlük istatistik modeli
class DailyStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    message_count = db.Column(db.Integer, default=0)
    earnings = db.Column(db.Float, default=0.0)
    
    user = db.relationship('User', backref='daily_stats')
    project = db.relationship('Project', backref='daily_stats')

# Kullanıcı modeli
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Tablo adını açıkça belirt
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Proje bazlı toplam kazanç
    momaily_total = db.Column(db.Float, default=0.0, nullable=False)
    liebesfun_total = db.Column(db.Float, default=0.0, nullable=False)
    beloops_total = db.Column(db.Float, default=0.0, nullable=False)
    
    # Proje bazlı toplam mesaj
    momaily_messages = db.Column(db.Integer, default=0, nullable=False)
    liebesfun_messages = db.Column(db.Integer, default=0, nullable=False)
    beloops_messages = db.Column(db.Integer, default=0, nullable=False)
    
    # Eski PHPESSID alanları kaldırıldı
    # momaily_phpessid = db.Column(db.String(255), nullable=True)
    # liebesfun_phpessid = db.Column(db.String(255), nullable=True)
    # beloops_phpessid = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_daily_stats(self, project_name):
        """Belirli bir projenin istatistiklerini getir"""
        project = Project.query.filter_by(name=project_name).first()
        if not project:
            return None
            
        return DailyStats.query.filter(
            DailyStats.user_id == self.id,
            DailyStats.project_id == project.id,
            DailyStats.date == datetime.now().date()
        ).first()
    
    def get_monthly_stats(self):
        """Son 30 günlük istatistiklerini getir"""
        return DailyStats.query.filter(
            DailyStats.user_id == self.id,
            DailyStats.date >= datetime.now().date() - timedelta(days=30)
        ).order_by(DailyStats.date.desc()).all()

# Chat mesaj modeli
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_user = db.Column(db.Boolean, default=True)  # True: kullanıcı mesajı, False: bot mesajı
    timestamp = db.Column(db.DateTime, default=dt.now)
    
    user = db.relationship('User', backref='chat_messages')
    project = db.relationship('Project', backref='chat_messages')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Admin kontrolü için decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('Bu sayfaya erişim yetkiniz yok!')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')

# Giriş sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.now()
            db.session.commit()
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')

# Kullanıcı paneli
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # auto_next parametresi varsa sadece yeni sohbet kontrolü yap
    if request.args.get('auto_next') == 'true':
        # Önce Beloops'u kontrol et
        phpessid = get_active_phpessid(current_user, 'beloops')
        if phpessid:
            try:
                beloops_convos = fetch_beloops_conversations(phpessid)
                if beloops_convos:
                    auto_project = 'beloops'
                    auto_p = beloops_convos[0]['p']
                    auto_id = beloops_convos[0]['id']
                    conversations = beloops_convos
            except Exception as e:
                print(f"DEBUG - Error fetching Beloops conversations: {str(e)}")
        
        # Sonra Momaily'yi kontrol et
        if get_active_phpessid(current_user, 'momaily'):
            try:
                conversations = fetch_momaily_conversations(get_active_phpessid(current_user, 'momaily'))
                if conversations:
                    return redirect(url_for('chat', project='momaily', p=conversations[0]['p'], id_=conversations[0]['id']))
            except Exception as e:
                print(f"DEBUG - Error fetching Momaily conversations: {str(e)}")
        
        # En son Liebesfun'u kontrol et
        if get_active_phpessid(current_user, 'liebesfun'):
            try:
                conversations = fetch_liebesfun_conversations(get_active_phpessid(current_user, 'liebesfun'))
                if conversations:
                    return redirect(url_for('chat', project='liebesfun', p=conversations[0]['p'], id_=conversations[0]['id']))
            except Exception as e:
                print(f"DEBUG - Error fetching Liebesfun conversations: {str(e)}")
        
        # Yeni sohbet bulunamadıysa dashboard'a dön
        return redirect(url_for('user_dashboard'))

    # Normal dashboard işlemleri
    today = germany_now().date()
    first_day = today.replace(day=1)
    all_stats = DailyCoinStats.query.filter(
        DailyCoinStats.user_id == current_user.id,
        DailyCoinStats.date >= first_day
    ).order_by(DailyCoinStats.date.desc()).all()
    
    stats_by_project = {'momaily': [], 'liebesfun': [], 'beloops': []}
    for stat in all_stats:
        if stat.project in stats_by_project:
            stats_by_project[stat.project].append(stat)
    
    salary = {}
    for project in ['momaily', 'liebesfun', 'beloops']:
        stats = stats_by_project[project]
        salary1_stats = [s for s in stats if 1 <= s.date.day <= 15]
        salary2_stats = [s for s in stats if 16 <= s.date.day <= 31]
        salary[project] = {
            'salary1': {
                'coins': sum(s.coins for s in salary1_stats),
                'messages': sum(s.messages for s in salary1_stats),
                'euro': round(sum(s.euro for s in salary1_stats), 2)
            },
            'salary2': {
                'coins': sum(s.coins for s in salary2_stats),
                'messages': sum(s.messages for s in salary2_stats),
                'euro': round(sum(s.euro for s in salary2_stats), 2)
            }
        }
    
    day = today.day
    active_salary_period = 1 if day <= 15 else 2
    salary_total = {'euro': 0.0, 'messages': 0}
    for project in ['momaily', 'liebesfun', 'beloops']:
        key = 'salary1' if active_salary_period == 1 else 'salary2'
        salary_total['euro'] += salary[project][key]['euro']
        salary_total['messages'] += salary[project][key]['messages']
    salary_total['euro'] = round(salary_total['euro'], 2)

    # Sohbetleri kontrol et
    conversations = []
    auto_p = None
    auto_id = None
    auto_project = None

    # Beloops'u kontrol et
    phpessid = get_active_phpessid(current_user, 'beloops')
    if phpessid:
        try:
            beloops_convos = fetch_beloops_conversations(phpessid)
            if beloops_convos:
                auto_project = 'beloops'
                auto_p = beloops_convos[0]['p']
                auto_id = beloops_convos[0]['id']
                conversations = beloops_convos
        except Exception as e:
            print(f"DEBUG - Error fetching Beloops conversations: {str(e)}")

    # Beloops'ta sohbet yoksa Momaily'yi kontrol et
    phpessid = get_active_phpessid(current_user, 'momaily')
    if not auto_project and phpessid:
        try:
            momaily_convos = fetch_momaily_conversations(phpessid)
            if momaily_convos:
                auto_project = 'momaily'
                auto_p = momaily_convos[0]['p']
                auto_id = momaily_convos[0]['id']
                conversations = momaily_convos
        except Exception as e:
            print(f"DEBUG - Error fetching Momaily conversations: {str(e)}")

    # Momaily'de de sohbet yoksa Liebesfun'u kontrol et
    phpessid = get_active_phpessid(current_user, 'liebesfun')
    if not auto_project and phpessid:
        try:
            liebesfun_convos = fetch_liebesfun_conversations(phpessid)
            if liebesfun_convos:
                auto_project = 'liebesfun'
                auto_p = liebesfun_convos[0]['p']
                auto_id = liebesfun_convos[0]['id']
                conversations = liebesfun_convos
        except Exception as e:
            print(f"DEBUG - Error fetching Liebesfun conversations: {str(e)}")
    
    return render_template(
        'user_dashboard.html',
        stats_by_project=stats_by_project,
        salary=salary,
        active_salary_period=active_salary_period,
        salary_total=salary_total,
        now=germany_now,
        auto_p=auto_p,
        auto_id=auto_id,
        auto_project=auto_project,
        conversations=conversations,
        todays_events=get_todays_calendar_events(current_user.id)
    )

# Admin paneli
@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Kullanıcı yönetimi sayfası
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Yeni kullanıcı oluşturma
@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        is_admin = request.form.get('is_admin') == 'on'

        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor!')
            return redirect(url_for('create_user'))

        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Kullanıcı başarıyla oluşturuldu!')
        return redirect(url_for('admin_users'))

    return render_template('admin_create_user.html')

# Kullanıcı düzenleme
@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.is_admin = request.form.get('is_admin') == 'on'
        
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
        
        db.session.commit()
        flash('Kullanıcı başarıyla güncellendi!')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_edit_user.html', user=user)

# Kullanıcı silme
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash('Kendinizi silemezsiniz!')
        return redirect(url_for('admin_users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('Kullanıcı başarıyla silindi!')
    return redirect(url_for('admin_users'))

# Çıkış
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Ayarlar sayfası
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    momaily_sessions = UserProjectSession.query.filter_by(user_id=current_user.id, project='momaily').all()
    liebesfun_sessions = UserProjectSession.query.filter_by(user_id=current_user.id, project='liebesfun').all()
    beloops_sessions = UserProjectSession.query.filter_by(user_id=current_user.id, project='beloops').all()
    return render_template('settings.html',
        momaily_sessions=momaily_sessions,
        liebesfun_sessions=liebesfun_sessions,
        beloops_sessions=beloops_sessions
    )

# Momaily giriş fonksiyonu
def momaily_login(phpessid):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        
        # SSL doğrulamasını devre dışı bırak
        requests.packages.urllib3.disable_warnings()
        
        # Test isteği gönder
        response = requests.get(
            'https://momaily.de/crazy_flirt/c.php',
            headers=headers,
            verify=False
        )
        
        # Response içeriğini kontrol et
        if 'Fehlermeldung' not in response.text and 'Info' not in response.text:
            return True, "Giriş başarılı"
        else:
            return False, "Geçersiz PHPESSID veya oturum süresi dolmuş"
            
    except Exception as e:
        return False, f"Bağlantı hatası: {str(e)}"

def fetch_momaily_messages(phpessid):
    """Fetch messages from Momaily chat"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    
    try:
        # SSL doğrulamasını devre dışı bırak
        requests.packages.urllib3.disable_warnings()
        
        # Chat sayfasını al
        response = requests.get(
            'https://momaily.de/crazy_flirt/c.php',
            headers=headers,
            verify=False
        )
        
        # Giriş durumunu kontrol et
        if 'Fehlermeldung' in response.text or 'Info' in response.text:
            return None, "Giriş başarısız. Lütfen PHPESSID'nizi kontrol edin."
            
        # HTML içeriğini parse et
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = parse_momaily_ajx_message_history(soup)
        
        # Tüm img'leri ve src'lerini yazdır
        all_imgs = soup.find_all('img')
        for i, img in enumerate(all_imgs):
            print(f"IMG {i}: {img}")
            print(f"IMG {i} SRC: {img.get('src')}")
        
        return messages, None
        
    except Exception as e:
        return None, f"Mesajlar alınırken bir hata oluştu: {str(e)}"

@app.route('/chat/<project>/<p>/<id_>', methods=['GET', 'POST'])
@login_required
def chat(project, p, id_):
    friend_request = False
    friend_accept_params = None
    friend_reject_params = None
    project = project.lower()
    if project not in ['momaily', 'liebesfun', 'beloops']:
        flash('Geçersiz proje!')
        return redirect(url_for('user_dashboard'))
    phpessid = request.args.get('phpessid')
    if not phpessid:
        phpessid = get_active_phpessid(current_user, project)
    # Doğru moderatör ismini bul: Bu PHPESSID ve proje için UserProjectSession'ı bul
    session = UserProjectSession.query.filter_by(user_id=current_user.id, project=project, phpessid=phpessid).order_by(UserProjectSession.created_at.desc()).first()
    moderator_name = session.moderator_name if session else None
    if not phpessid:
        flash(f'{project.capitalize()} için oturum bulunamadı!')
        return redirect(url_for('user_dashboard'))
    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            print(f"[DEBUG] Sending message: {message}")
            success = False
            if project == 'momaily':
                success = send_momaily_message(phpessid, p, id_, message)
            elif project == 'liebesfun':
                success = send_liebesfun_message(phpessid, p, id_, message)
            elif project == 'beloops':
                success = send_beloops_message(phpessid, p, id_, message)
            print(f"[DEBUG] Message send result: {success}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': success})
    
    # Force reload if requested
    force_reload = request.args.get('reload') == 'true'
    
    # Mesajları getir
    messages = []
    customer = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
    fake = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
    
    if project == 'momaily':
        messages = fetch_all_momaily_messages(phpessid, p, id_)
        # Momaily profil bilgilerini getir
        soup, _, friend_request, friend_accept_params, friend_reject_params = fetch_momaily_message_screen(phpessid)
        if soup:
            data = parse_momaily_full_screen(soup)
            customer = data['customer']
            fake = data['fake']
    elif project == 'liebesfun':
        messages = fetch_all_liebesfun_messages(phpessid, p, id_)
        # Liebesfun profil bilgilerini getir
        soup, _ = fetch_liebesfun_message_screen(phpessid)
        if soup:
            data = parse_liebesfun_full_screen(soup)
            customer = data['customer']
            fake = data['fake']
    elif project == 'beloops':
        messages = fetch_all_beloops_messages(phpessid, p, id_)
        # Profil bilgilerini çek
        url = f"https://beloops.com/Chat/privat_postfach.php?p={p}&id={id_}&action=read"
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        try:
            response = requests.get(url, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Müşteri profil ismi ve foto
            customer = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
            fake = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
            # Müşteri ismi
            cust_span = soup.find('span', style=lambda x: x and '#4080ff' in x)
            if cust_span:
                customer['name'] = cust_span.get_text(strip=True)
            cust_img = soup.find('img', src=lambda x: x and f'/gallery/{id_}/' in x)
            if cust_img:
                customer['photo'] = cust_img['src'] if cust_img['src'].startswith('http') else 'https://beloops.com' + cust_img['src']
            # Fake ismi
            fake_span = soup.find('span', style=lambda x: x and '#ff0088' in x)
            if fake_span:
                fake['name'] = fake_span.get_text(strip=True)
            fake_img = soup.find('img', src=lambda x: x and f'/gallery/{p}/' in x)
            if fake_img:
                fake['photo'] = fake_img['src'] if fake_img['src'].startswith('http') else 'https://beloops.com' + fake_img['src']
        except Exception as e:
            print(f"[DEBUG] Beloops profil çekme hatası: {e}")
            customer = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
            fake = {'name': '', 'photo': '', 'age': '', 'desc': '', 'city': '', 'job': '', 'working_hours': '', 'status': ''}
    
    print(f"[DEBUG] Total messages fetched: {len(messages)}")

    # --- ProfileInfo ve DialogInfo verilerini çek ---
    customer_profileinfo = ProfileInfo.query.filter_by(user_id=current_user.id, project=project, p=p, id_=id_, type='customer').first()
    fake_profileinfo = ProfileInfo.query.filter_by(user_id=current_user.id, project=project, p=p, id_=id_, type='fake').first()
    dialog_info = DialogInfo.query.filter_by(user_id=current_user.id, project=project, p=p, id_=id_).first()

    # Bugünkü takvim olaylarını ekle
    todays_events = get_todays_calendar_events(current_user.id)

    # --- Template'e gönder ---
    return render_template('chat.html', 
                         messages=messages, 
                         project=project,
                         p=p,
                         id_=id_,
                         customer=customer,
                         fake=fake,
                         friend_request=friend_request,
                         friend_accept_params=friend_accept_params,
                         friend_reject_params=friend_reject_params,
                         customer_profileinfo=customer_profileinfo,
                         fake_profileinfo=fake_profileinfo,
                         dialog_info=dialog_info,
                         todays_events=todays_events,
                         force_reload=force_reload,
                         moderator_name=moderator_name
    )

def get_powerchat_link(phpessid):
    """Ana chat sayfasından POWERCHAT 1:1 linkini çek"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get('https://momaily.de/crazy_flirt/c.php', headers=headers, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    # POWERCHAT 1:1 butonunu bul
    divs = soup.find_all('div', onclick=True)
    for div in divs:
        onclick = div.get('onclick', '')
        if 'p_postfach.php' in onclick:
            # Linki çek
            start = onclick.find("window.location.href='") + len("window.location.href='")
            end = onclick.find("'", start)
            link = onclick[start:end]
            # Tam URL oluştur
            if not link.startswith('http'):
                link = 'https://momaily.de/crazy_flirt/' + link
            return link
    return None

def fetch_momaily_message_screen(phpessid):
    """POWERCHAT linkine gidip mesaj ekranı HTML'ini ve mesaj geçmişini döndür"""
    powerchat_url = get_powerchat_link(phpessid)
    if not powerchat_url:
        return None, 'POWERCHAT linki bulunamadı.'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(powerchat_url, headers=headers, verify=False)
    if response.status_code != 200:
        return None, 'Mesaj ekranı yüklenemedi.'
    soup = BeautifulSoup(response.text, "html.parser")
    # Debug: Save HTML for inspection
    with open("debug_momaily_response.html", "w", encoding="utf-8") as f:
        f.write(response.text)
    friend_request = False
    friend_accept_params = None
    friend_reject_params = None
    # 1. Kabul et butonu var mı?
    accept_btn = soup.find('input', {'type': 'submit', 'value': 'Freundesanfrage jetzt bestätigen'})
    if accept_btn:
        print('[DEBUG] Freundesanfrage jetzt bestätigen butonu bulundu!')
        friend_request = True
        accept_form = accept_btn.find_parent('form')
        if accept_form:
            action = accept_form.get('action', 'p_postfach.php')
            inputs = {i.get('name'): i.get('value') for i in accept_form.find_all('input', {'name': True, 'value': True})}
            friend_accept_params = {'action': action, 'inputs': inputs}
    # 2. Reddet butonu var mı?
    reject_btn = soup.find('input', {'type': 'submit', 'value': 'Freundesanfrage löschen'})
    if reject_btn:
        print('[DEBUG] Freundesanfrage löschen butonu bulundu!')
        reject_form = reject_btn.find_parent('form')
        if reject_form:
            action = reject_form.get('action', 'p_meinefreunde.php')
            inputs = {i.get('name'): i.get('value') for i in reject_form.find_all('input', {'name': True, 'value': True})}
            friend_reject_params = {'action': action, 'inputs': inputs}
    # 3. Eğer butonlar yoksa, yazıyı kontrol et
    if not friend_request:
        span = soup.find('span', string=lambda x: x and 'Freundesanfrage jetzt bestätigen' in x)
        if span:
            print('[DEBUG] Freundesanfrage yazısı bulundu!')
            # Formu yukarıdan aşağıya ara
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'submit', 'value': 'Freundesanfrage jetzt bestätigen'}):
                    action = form.get('action', 'p_postfach.php')
                    inputs = {i.get('name'): i.get('value') for i in form.find_all('input', {'name': True, 'value': True})}
                    friend_accept_params = {'action': action, 'inputs': inputs}
                    friend_request = True
                if form.find('input', {'type': 'submit', 'value': 'Freundesanfrage löschen'}):
                    action = form.get('action', 'p_meinefreunde.php')
                    inputs = {i.get('name'): i.get('value') for i in form.find_all('input', {'name': True, 'value': True})}
                    friend_reject_params = {'action': action, 'inputs': inputs}
    print(f'[DEBUG] friend_request: {friend_request}, accept_params: {friend_accept_params}, reject_params: {friend_reject_params}')
    # Tüm img'leri ve src'lerini yazdır
    all_imgs = soup.find_all('img')
    for i, img in enumerate(all_imgs):
        print(f"IMG {i}: {img}")
        print(f"IMG {i} SRC: {img.get('src')}")
    return soup, None, friend_request, friend_accept_params, friend_reject_params

def parse_momaily_message_history(soup):
    """Mesaj ekranı HTML'inden mesaj geçmişini parse et"""
    messages = []
    # Öncelikle <div id='showpm'> içini kontrol et
    showpm_div = soup.find('div', id='showpm')
    if showpm_div:
        # Her mesajı ayır (ör: <div> veya <tr> olabilir, ya da satır satır text)
        # Eğer img 'wait.gif' varsa, mesaj yok demektir
        if showpm_div.find('img', {'src': 'https://momaily.de/pic/wait.gif'}):
            return messages  # Henüz mesaj yüklenmemiş
        # Satır satır text olarak mesajlar olabilir
        for child in showpm_div.find_all(['div', 'tr', 'p'], recursive=True):
            text = child.get_text(strip=True)
            if text:
                messages.append({
                    'sender': '',  # Şimdilik göndereni ayırt edemiyoruz
                    'text': text,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
        # Eğer yukarıda mesaj bulunamazsa, fallback olarak tüm text'i ekle
        if not messages:
            text = showpm_div.get_text(strip=True)
            if text:
                messages.append({
                    'sender': '',
                    'text': text,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
        return messages
    # Fallback: eski tablo mantığı
    tables = soup.find_all('table')
    if len(tables) < 2:
        return messages  # Mesaj tablosu yok
    message_table = tables[1]
    rows = message_table.find_all('tr')
    for row in rows:
        cells = row.find_all('td')
        if len(cells) >= 2:
            sender = cells[0].get_text(strip=True)
            text = cells[1].get_text(strip=True)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            messages.append({
                'sender': sender,
                'text': text,
                'timestamp': timestamp
            })
    return messages

def parse_momaily_full_screen(soup):
    data = {
        'customer': {},
        'fake': {},
        'messages': []
    }
    main_tables = soup.find_all('table', style=lambda x: x and 'width:350px' in x)
    if len(main_tables) >= 2:
        left_table = main_tables[0]
        customer_name = left_table.find('span', style=lambda x: x and 'color:#4080ff' in x)
        data['customer']['name'] = customer_name.get_text(strip=True) if customer_name else ''
        customer_img = left_table.find('img', src=lambda x: x and 'profilbilder' in x)
        print("DEBUG customer_img:", customer_img)
        if customer_img:
            src = customer_img['src']
            if src.startswith('http'):
                pass
            elif src.startswith('../profilbilder/'):
                src = 'https://momaily.de' + src[2:]
            elif src.startswith('/profilbilder/'):
                src = 'https://momaily.de' + src
            elif src.startswith('profilbilder'):
                src = 'https://momaily.de/' + src
            else:
                src = 'https://momaily.de/' + src
            data['customer']['photo'] = src
        else:
            data['customer']['photo'] = ''
        right_table = main_tables[1]
        fake_name = right_table.find('span', style=lambda x: x and 'color:#ff0088' in x)
        data['fake']['name'] = fake_name.get_text(strip=True) if fake_name else ''
        fake_img = right_table.find('img', src=lambda x: x and 'profilbilder' in x)
        print("DEBUG fake_img:", fake_img)
        if fake_img:
            src = fake_img['src']
            if src.startswith('http'):
                pass
            elif src.startswith('../profilbilder/'):
                src = 'https://momaily.de' + src[2:]
            elif src.startswith('/profilbilder/'):
                src = 'https://momaily.de' + src
            elif src.startswith('profilbilder'):
                src = 'https://momaily.de/' + src
            else:
                src = 'https://momaily.de/' + src
            data['fake']['photo'] = src
        else:
            data['fake']['photo'] = ''
    data['messages'] = parse_momaily_message_history(soup)
    return data

def fetch_momaily_messages_ajax(phpessid, p, id_, start=0):
    print(f"[DEBUG] Fetching messages: p={p}, id={id_}, start={start}")
    url = f"https://momaily.de/crazy_flirt/p_postfach.php?p={p}&ajax=next_message&id={id_}&start={start}"
    headers = {
        'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://momaily.de',
        'Referer': f'https://momaily.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=read',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'X-Prototype-Version': '1.7',
        'X-Requested-With': 'XMLHttpRequest',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        print(f"[DEBUG] Making request to URL: {url}")
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, headers=headers, verify=False)
        print(f"[DEBUG] Response status: {response.status_code}")
        print(f"[DEBUG] Response text: {response.text[:200]}...")  # İlk 200 karakteri yazdır
        
        if response.status_code != 200:
            print(f"[DEBUG] Error response: {response.text}")
            return None, f"HTTP error: {response.status_code}"
            
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = parse_momaily_ajx_message_history(soup)
        print(f"[DEBUG] Found {len(messages)} messages")
        return messages, None
    except Exception as e:
        print(f"[DEBUG] Exception: {str(e)}")
        return None, str(e)

def fetch_all_momaily_messages(phpessid, p, id_):
    print(f"[DEBUG] Starting fetch_all_momaily_messages with p={p}, id={id_}")
    all_messages = []
    start = 0
    while True:
        print(f"[DEBUG] Fetching messages batch starting at {start}")
        messages, error = fetch_momaily_messages_ajax(phpessid, p, id_, start)
        if error:
            print(f"[DEBUG] Error fetching messages: {error}")
            break
        if not messages:
            print("[DEBUG] No messages returned")
            break
        print(f"[DEBUG] Got {len(messages)} messages in this batch")
        all_messages.extend(messages)
        if len(messages) < 10:  # 10'dan azsa son sayfa
            print("[DEBUG] Less than 10 messages received, assuming last page")
            break
        start += len(messages)
    print(f"[DEBUG] Total messages fetched: {len(all_messages)}")
    return all_messages

def parse_momaily_ajx_message_history(soup):
    messages = []
    print("[DEBUG] Starting to parse messages from HTML")
    
    # Debug: Save the HTML to a file
    with open("debug_message_parse.html", "w", encoding="utf-8") as f:
        f.write(str(soup))
    
    for msg_table in soup.find_all('table', style=lambda x: x and ('float:left' in x or 'float:right' in x)):
        print("[DEBUG] Found message table")
        is_user = 'float:right' in msg_table.get('style', '')
        print(f"[DEBUG] Message is from user: {is_user}")

        rel_div = msg_table.find('div', style=lambda x: x and 'position:relative' in x and 'color:#000000' in x)
        if not rel_div:
            print("[DEBUG] No relative div found, skipping message")
            continue

        date_td = rel_div.find('td', style=lambda x: x and 'width:150px' in x)
        timestamp = date_td.get_text(strip=True) if date_td else ''
        print(f"[DEBUG] Found timestamp: {timestamp}")

        sender_span = rel_div.find('span', style=lambda x: x and 'font-size:10px;' in x)
        sender = sender_span.get_text(strip=True) if sender_span and sender_span.text else ("Siz" if is_user else "Karşı Taraf")
        print(f"[DEBUG] Found sender: {sender}")

        body_div = rel_div.find('div', id=lambda x: x and x.startswith('body_'))
        message_text = ""
        image_url = None
        if body_div:
            # Metin varsa ekle
            message_text = body_div.get_text(separator="\n", strip=True)
            print(f"[DEBUG] Found message text: {message_text[:50]}...")
            # Resim varsa ekle
            img = body_div.find('img')
            if img and img.get('src'):
                image_url = img['src']
                print(f"[DEBUG] Found image URL: {image_url}")
                # Eğer mesajda zaten <img> etiketi yoksa, mesajın sonuna ekle
                if img['src'] not in message_text:
                    message_text += f'<br><img src="{img["src"]}" style="max-width:90%;border-radius:10px;">'
            # Video varsa ekle
            video = body_div.find('video')
            if video and video.get('src'):
                if video['src'] not in message_text:
                    message_text += f'<br><video src="{video["src"]}" controls style="max-width:90%;border-radius:10px;"></video>'

        print("DEBUG message.text:", message_text)

        messages.append({
            'sender': sender,
            'text': message_text,
            'timestamp': timestamp,
            'is_user': is_user,
            'image_url': image_url
        })
    
    print(f"[DEBUG] Total messages parsed: {len(messages)}")
    return messages

def send_momaily_message(phpessid, p, id_, message):
    url = f"https://momaily.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=send"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': f'https://momaily.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=read',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://momaily.de',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    cookies = {'PHPSESSID': phpessid}
    data = {'inhalt': message}
    requests.packages.urllib3.disable_warnings()
    response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)
    print(f"[DEBUG] Send message response: {response.status_code} - {response.text}")
    return response.status_code == 200

def fetch_momaily_conversations(phpessid):
    print(f"[DEBUG] Starting fetch_momaily_conversations with PHPSESSID: {phpessid[:5]}...")
    url = "https://momaily.de/crazy_flirt/p_postfach.php"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Referer': 'https://momaily.de/crazy_flirt/c.php',
        'Origin': 'https://momaily.de',
        'Cookie': f'PHPSESSID={phpessid}',
    }
    cookies = {'PHPSESSID': phpessid}
    
    try:
        print("[DEBUG] Making request to fetch conversations...")
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, cookies=cookies, verify=False)
        print(f"[DEBUG] Response status code: {response.status_code}")
        
        # Save response for debugging
        with open("debug_momaily_conversations.html", "w", encoding="utf-8") as f:
            f.write(response.text)
            
        if 'login.php' in response.url:
            print("[DEBUG] ERROR: Redirected to login page, session likely expired")
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        conversations = []

        # Look for POWERCHAT links
        divs = soup.find_all('div', onclick=True)
        print(f"[DEBUG] Found {len(divs)} divs with onclick attribute")
        
        for div in divs:
            onclick = div.get('onclick', '')
            if 'POWERCHAT' in div.text and 'p_postfach.php' in onclick:
                print(f"[DEBUG] Found POWERCHAT div: {div.text}")
                # Extract conversation info
                start = onclick.find("window.location.href='") + len("window.location.href='")
                end = onclick.find("'", start)
                link = onclick[start:end]
                
                # Parse p and id from link
                params = dict(parse_qsl(urlparse(link).query))
                if 'p' in params and 'id' in params:
                    conversations.append({
                        'p': params['p'],
                        'id': params['id'],
                        'name': div.get_text(strip=True)
                    })
                    print(f"[DEBUG] Added conversation: p={params['p']}, id={params['id']}")
        
        print(f"[DEBUG] Total conversations found: {len(conversations)}")
        return conversations
        
    except Exception as e:
        print(f"[DEBUG] Exception in fetch_momaily_conversations: {str(e)}")
        return []

def fetch_liebesfun_conversations(phpessid):
    print(f"[DEBUG] Starting fetch_liebesfun_conversations with PHPSESSID: {phpessid[:5]}...")
    url = "https://liebesfun.de/crazy_flirt/p_postfach.php"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Referer': 'https://liebesfun.de/crazy_flirt/c.php',
        'Origin': 'https://liebesfun.de',
        'Cookie': f'PHPSESSID={phpessid}',
    }
    cookies = {'PHPSESSID': phpessid}
    
    try:
        print("[DEBUG] Making request to fetch conversations...")
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, cookies=cookies, verify=False)
        print(f"[DEBUG] Response status code: {response.status_code}")
        
        # Save response for debugging
        with open("debug_liebesfun_conversations.html", "w", encoding="utf-8") as f:
            f.write(response.text)
            
        if 'login.php' in response.url:
            print("[DEBUG] ERROR: Redirected to login page, session likely expired")
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        conversations = []

        # Look for POWERCHAT links
        divs = soup.find_all('div', onclick=True)
        print(f"[DEBUG] Found {len(divs)} divs with onclick attribute")
        
        for div in divs:
            onclick = div.get('onclick', '')
            if 'POWERCHAT' in div.text and 'p_postfach.php' in onclick:
                print(f"[DEBUG] Found POWERCHAT div: {div.text}")
                # Extract conversation info
                start = onclick.find("window.location.href='") + len("window.location.href='")
                end = onclick.find("'", start)
                link = onclick[start:end]
                
                # Parse p and id from link
                params = dict(parse_qsl(urlparse(link).query))
                if 'p' in params and 'id' in params:
                    conversations.append({
                        'p': params['p'],
                        'id': params['id'],
                        'name': div.get_text(strip=True)
                    })
                    print(f"[DEBUG] Added conversation: p={params['p']}, id={params['id']}")
        
        print(f"[DEBUG] Total conversations found: {len(conversations)}")
        return conversations
        
    except Exception as e:
        print(f"[DEBUG] Exception in fetch_liebesfun_conversations: {str(e)}")
        return []

def fetch_liebesfun_messages_ajax(phpessid, p, id_, start=0):
    # First check session
    if not check_liebesfun_session(phpessid):
        print("[DEBUG] Invalid session, cannot fetch messages")
        return None, "Session invalid or expired"
        
    print(f"[DEBUG] Starting fetch_liebesfun_messages_ajax with PHPSESSID: {phpessid[:5]}...")
    url = f"https://liebesfun.de/crazy_flirt/p_postfach.php?p={p}&ajax=next_message&id={id_}&start={start}"
    headers = {
        'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://liebesfun.de',
        'Referer': f'https://liebesfun.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=read',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'X-Prototype-Version': '1.7',
        'X-Requested-With': 'XMLHttpRequest',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        print(f"[DEBUG] Making request to URL: {url}")
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, headers=headers, verify=False)
        print(f"[DEBUG] Response status code: {response.status_code}")
        print(f"[DEBUG] Response headers: {dict(response.headers)}")
        
        if response.status_code == 302 or 'login.php' in response.url:
            print("[DEBUG] ERROR: Redirected to login page, session expired")
            return None, "Session expired"
            
        if response.status_code != 200:
            print(f"[DEBUG] Error: Non-200 status code received: {response.status_code}")
            return None, f"HTTP error: {response.status_code}"
        
        # Save response for debugging
        with open(f"debug_liebesfun_messages_{start}.html", "w", encoding="utf-8") as f:
            f.write(response.text)
            
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = parse_liebesfun_message_history(soup)
        print(f"[DEBUG] Successfully parsed {len(messages)} messages")
        return messages, None
    except Exception as e:
        print(f"[DEBUG] Exception in fetch_liebesfun_messages_ajax: {str(e)}")
        return None, str(e)

def fetch_all_liebesfun_messages(phpessid, p, id_):
    """Tüm Liebesfun mesajlarını getir"""
    all_messages = []
    start = 0
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            messages, error = fetch_liebesfun_messages_ajax(phpessid, p, id_, start)
            if error:
                print(f"[DEBUG] Error fetching Liebesfun messages: {error}")
                retry_count += 1
                time.sleep(1)  # 1 saniye bekle
                continue
                
            if not messages:
                break
                
            all_messages.extend(messages)
            
            if len(messages) < 10:  # 10'dan azsa son sayfa
                break
                
            start += len(messages)
            retry_count = 0  # Başarılı olunca retry sayacını sıfırla
            
        except Exception as e:
            print(f"[DEBUG] Exception in fetch_all_liebesfun_messages: {str(e)}")
            retry_count += 1
            time.sleep(1)  # 1 saniye bekle
            continue
    
    print(f"[DEBUG] Total Liebesfun messages fetched: {len(all_messages)}")
    return all_messages

def parse_liebesfun_message_history(soup):
    """Mesaj ekranı HTML'inden mesaj geçmişini parse et"""
    messages = []
    print("[DEBUG] Starting to parse Liebesfun messages")
    
    # Debug: Save the HTML to a file
    with open("debug_liebesfun_message_parse.html", "w", encoding="utf-8") as f:
        f.write(str(soup))
    
    for msg_table in soup.find_all('table', style=lambda x: x and ('float:left' in x or 'float:right' in x)):
        print("[DEBUG] Found message table")
        is_user = 'float:right' in msg_table.get('style', '')
        print(f"[DEBUG] Message is from user: {is_user}")

        rel_div = msg_table.find('div', style=lambda x: x and 'position:relative' in x and 'color:#000000' in x)
        if not rel_div:
            print("[DEBUG] No relative div found, skipping message")
            continue

        date_td = rel_div.find('td', style=lambda x: x and 'width:150px' in x)
        timestamp = date_td.get_text(strip=True) if date_td else ''
        print(f"[DEBUG] Found timestamp: {timestamp}")

        sender_span = rel_div.find('span', style=lambda x: x and 'font-size:10px;' in x)
        sender = sender_span.get_text(strip=True) if sender_span and sender_span.text else ("Siz" if is_user else "Karşı Taraf")
        print(f"[DEBUG] Found sender: {sender}")

        body_div = rel_div.find('div', id=lambda x: x and x.startswith('body_'))
        message_text = ""
        image_url = None
        if body_div:
            # Metin varsa ekle
            message_text = body_div.get_text(separator="\n", strip=True)
            print(f"[DEBUG] Found message text: {message_text[:50]}...")
            # Resim varsa ekle
            img = body_div.find('img')
            if img and img.get('src'):
                image_url = img['src']
                print(f"[DEBUG] Found image URL: {image_url}")
                # Eğer mesajda zaten <img> etiketi yoksa, mesajın sonuna ekle
                if img['src'] not in message_text:
                    message_text += f'<br><img src="{img["src"]}" style="max-width:90%;border-radius:10px;">'
            # Video varsa ekle
            video = body_div.find('video')
            if video and video.get('src'):
                if video['src'] not in message_text:
                    message_text += f'<br><video src="{video["src"]}" controls style="max-width:90%;border-radius:10px;"></video>'

        print(f"[DEBUG] Final message text: {message_text[:50]}...")

        messages.append({
            'sender': sender,
            'text': message_text,
            'timestamp': timestamp,
            'is_user': is_user,
            'image_url': image_url
        })
    
    print(f"[DEBUG] Total messages parsed: {len(messages)}")
    return messages

def fetch_liebesfun_message_screen(phpessid):
    """POWERCHAT linkine gidip mesaj ekranı HTML'ini ve mesaj geçmişini döndür"""
    powerchat_url = get_liebesfun_powerchat_link(phpessid)
    if not powerchat_url:
        return None, 'POWERCHAT linki bulunamadı.'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(powerchat_url, headers=headers, verify=False)
    if response.status_code != 200:
        return None, 'Mesaj ekranı yüklenemedi.'
    soup = BeautifulSoup(response.text, 'html.parser')
    with open("debug_liebesfun_response.html", "w", encoding="utf-8") as f:
        f.write(response.text)
    # Tüm img'leri ve src'lerini yazdır
    all_imgs = soup.find_all('img')
    for i, img in enumerate(all_imgs):
        print(f"IMG {i}: {img}")
        print(f"IMG {i} SRC: {img.get('src')}")
    return soup, None

def get_liebesfun_powerchat_link(phpessid):
    """Ana chat sayfasından POWERCHAT 1:1 linkini çek"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get('https://liebesfun.de/crazy_flirt/c.php', headers=headers, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    # POWERCHAT 1:1 butonunu bul
    divs = soup.find_all('div', onclick=True)
    for div in divs:
        onclick = div.get('onclick', '')
        if 'p_postfach.php' in onclick:
            # Linki çek
            start = onclick.find("window.location.href='") + len("window.location.href='")
            end = onclick.find("'", start)
            link = onclick[start:end]
            # Tam URL oluştur
            if not link.startswith('http'):
                link = 'https://liebesfun.de/crazy_flirt/' + link
            return link
    return None

def parse_liebesfun_full_screen(soup):
    """Liebesfun mesaj ekranından müşteri/fake bilgileri, fotoğraflar ve mesaj geçmişini döndür"""
    data = {
        'customer': {},
        'fake': {},
        'messages': []
    }
    # Sol müşteri paneli (ilk büyük <td>), sağ fake paneli (ikinci büyük <td>)
    main_tables = soup.find_all('table', style=lambda x: x and 'width:350px' in x)
    if len(main_tables) >= 2:
        # Müşteri bilgileri
        left_table = main_tables[0]
        customer_name = left_table.find('span', style=lambda x: x and 'color:#4080ff' in x)
        data['customer']['name'] = customer_name.get_text(strip=True) if customer_name else ''
        customer_img = left_table.find('img', src=lambda x: x and 'profilbilder' in x)
        if customer_img:
            src = customer_img['src']
            if src.startswith('http'):
                pass
            elif src.startswith('../profilbilder/'):
                src = 'https://liebesfun.de' + src[2:]
            elif src.startswith('/profilbilder/'):
                src = 'https://liebesfun.de' + src
            elif src.startswith('profilbilder'):
                src = 'https://liebesfun.de/' + src
            else:
                src = 'https://liebesfun.de/' + src
            data['customer']['photo'] = src
        else:
            data['customer']['photo'] = ''
        # Fake bilgileri
        right_table = main_tables[1]
        fake_name = right_table.find('span', style=lambda x: x and 'color:#ff0088' in x)
        data['fake']['name'] = fake_name.get_text(strip=True) if fake_name else ''
        fake_img = right_table.find('img', src=lambda x: x and 'profilbilder' in x)
        if fake_img:
            src = fake_img['src']
            if src.startswith('http'):
                pass
            elif src.startswith('../profilbilder/'):
                src = 'https://liebesfun.de' + src[2:]
            elif src.startswith('/profilbilder/'):
                src = 'https://liebesfun.de' + src
            elif src.startswith('profilbilder'):
                src = 'https://liebesfun.de/' + src
            else:
                src = 'https://liebesfun.de/' + src
            data['fake']['photo'] = src
        else:
            data['fake']['photo'] = ''
    # Mesaj geçmişi
    data['messages'] = parse_liebesfun_message_history(soup)
    return data

def fetch_beloops_conversations(phpessid):
    url = "https://beloops.com/Chat/privat_base.php"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Referer': 'https://beloops.com/Chat/privat_base.php',
        'Origin': 'https://beloops.com',
        'Cookie': f'PHPSESSID={phpessid}',
    }
    cookies = {'PHPSESSID': phpessid}
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, cookies=cookies, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    conversations = []

    # Eski: <a href="privat_postfach.php?p=...&id=...&action=read">
    for a in soup.find_all('a', href=True):
        href = a['href']
        if 'privat_postfach.php?p=' in href and '&id=' in href:
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(href).query)
            p = qs.get('p', [None])[0]
            id_ = qs.get('id', [None])[0]
            name = a.get_text(strip=True)
            if p and id_:
                conversations.append({'p': p, 'id': id_, 'name': name})

    # Yeni: <div onclick="window.location.href='privat_postfach.php?p=...&id=...&action=read...">
    for div in soup.find_all('div', onclick=True):
        onclick = div['onclick']
        if "window.location.href='privat_postfach.php?p=" in onclick:
            match = re.search(r"privat_postfach\.php\?p=(\d+)&id=(\d+)", onclick)
            if match:
                p = match.group(1)
                id_ = match.group(2)
                name = div.get_text(strip=True)
                conversations.append({'p': p, 'id': id_, 'name': name})

    with open("debug_beloops_conversations.html", "w", encoding="utf-8") as f:
        f.write(response.text)
    return conversations

def fetch_beloops_messages_ajax(phpessid, p, id_, start=0):
    url = f"https://beloops.com/Chat/privat_postfach.php?p={p}&ajax=next_message&id={id_}&start={start}"
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Connection': 'keep-alive',
        'Referer': f'https://beloops.com/Chat/privat_postfach.php?p={p}&id={id_}&action=read',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    cookies = {
        'PHPSESSID': phpessid,
        'cf': 'https://www.google.com/'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, cookies=cookies, verify=False)
        if response.status_code != 200:
            return None, f"HTTP error: {response.status_code}"
        soup = BeautifulSoup(response.text, 'html.parser')
        # TODO: Beloops mesaj parse fonksiyonu ekle (parse_beloops_message_history)
        messages = parse_beloops_message_history(soup)
        return messages, None
    except Exception as e:
        return None, str(e)

def parse_beloops_message_history(soup):
    """Beloops mesaj ekranı HTML'inden mesaj geçmişini parse et"""
    messages = []
    # Her mesaj bir <div id='mes_...'> içinde
    for mes_div in soup.find_all('div', id=lambda x: x and x.startswith('mes_')):
        # Tarih ve saat
        date_td = mes_div.find_previous('td', style=lambda x: x and 'width:150px' in x)
        timestamp = date_td.get_text(strip=True) if date_td else ''
        
        # Mesaj metni ve resim
        body_div = mes_div.find('div', id=lambda x: x and x.startswith('body_'))
        message_text = ""
        if body_div:
            # Önce metni al
            message_text = body_div.get_text(separator="\n", strip=True)
            
            # Resim varsa ekle
            img = body_div.find('img')
            if img and img.get('src'):
                img_src = img['src']
                if not img_src.startswith('http'):
                    img_src = f"https://beloops.com{img_src}"
                message_text += f'<br><img src="{img_src}" alt="image" style="max-width:95%;border-radius:10px;">'
        
        # Kimden geldiği (float:left = karşıdan, float:right = kullanıcıdan)
        is_user = 'float:right' in mes_div.get('style', '')
        
        messages.append({
            'sender': 'Siz' if is_user else 'Karşı Taraf',
            'text': message_text,
            'timestamp': timestamp,
            'is_user': is_user
        })
    
    return messages

def send_liebesfun_message(phpessid, p, id_, message):
    url = f"https://liebesfun.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=send"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': f'https://liebesfun.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=read',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://liebesfun.de',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    cookies = {'PHPSESSID': phpessid}
    data = {'inhalt': message}
    requests.packages.urllib3.disable_warnings()
    response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)
    return response.status_code == 200

def check_liebesfun_session(phpessid):
    """Check if Liebesfun session is valid and try to refresh if needed"""
    print(f"[DEBUG] Checking Liebesfun session: {phpessid[:5]}...")

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'PHPSESSID={phpessid}'
    }

    try:
        # First try to access the main page
        requests.packages.urllib3.disable_warnings()
        response = requests.get('https://liebesfun.de/crazy_flirt/c.php', headers=headers, verify=False, allow_redirects=False)

        # If we get redirected or get a login page, session is invalid
        if response.status_code == 302 or 'login.php' in response.url:
            print("[DEBUG] Session invalid or expired")
            return False

        # Check if we got the expected content
        if 'POWERCHAT' not in response.text:
            print("[DEBUG] Session appears invalid - no POWERCHAT found")
            return False

        print("[DEBUG] Session appears valid")
        return True

    except Exception as e:
        print(f"[DEBUG] Error checking session: {str(e)}")
        return False

@app.route('/send_photo/<project>/<p>/<id_>', methods=['GET', 'POST'])
@login_required
def send_photo(project, p, id_):
    project = project.lower()
    if project not in ['momaily', 'liebesfun', 'beloops']:
        flash('Geçersiz proje!', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Get user's PHPESSID for the project
    phpessid = None
    if project == 'momaily':
        phpessid = current_user.momaily_phpessid
    elif project == 'liebesfun':
        phpessid = current_user.liebesfun_phpessid
    elif project == 'beloops':
        phpessid = current_user.beloops_phpessid
    
    if not phpessid:
        flash('Oturum bulunamadı! Lütfen ayarlardan oturum bilgilerinizi güncelleyin.', 'error')
        return redirect(url_for('settings'))
    
    # Handle photo sending
    if request.method == 'POST':
        photo_name = request.form.get('photo_name')
        if not photo_name:
            flash('Fotoğraf seçilmedi!', 'error')
            return redirect(url_for('send_photo', project=project, p=p, id_=id_))
        
        # Send photo based on project
        success = False
        if project == 'momaily':
            url = f"https://momaily.de/crazy_flirt/p_postfach.php?p={p}&id={id_}&action=portfolio&name={photo_name}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
                'Referer': f'https://momaily.de/crazy_flirt/p_sendphoto.php?p={p}&id={id_}&action=menu',
            }
            cookies = {
                'PHPSESSID': phpessid
            }
            response = requests.get(url, headers=headers, cookies=cookies, verify=False)
            print(response.status_code, response.text[:300])
            success = response.status_code == 200
        elif project == 'liebesfun':
            success = send_liebesfun_message(phpessid, p, id_, f'<img src="{photo_name}" style="max-width:90%;border-radius:10px;">')
        elif project == 'beloops':
            url = f"https://beloops.com/Chat/privat_sendphoto.php?p={p}&id={id_}&action=menu"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
                'Cookie': f'PHPSESSID={phpessid}'
            }
            try:
                response = requests.get(url, headers=headers, verify=False)
                success = response.status_code == 200
            except Exception as e:
                print(f"[DEBUG] Error sending Beloops photo: {str(e)}")
                success = False
        
        if success:
            flash('Fotoğraf başarıyla gönderildi!', 'success')
            return redirect(url_for('chat', project=project, p=p, id_=id_))
        else:
            flash('Fotoğraf gönderilemedi!', 'error')
            return redirect(url_for('send_photo', project=project, p=p, id_=id_))
    
    # Fetch available photos
    photos = []
    if project == 'momaily':
        url = f"https://momaily.de/crazy_flirt/p_sendphoto.php?p={p}&id={id_}&action=menu"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        try:
            response = requests.get(url, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Save response for debugging
            with open('debug_momaily_photos.html', 'w', encoding='utf-8') as f:
                f.write(response.text)
            for img in soup.find_all('img', src=lambda x: x and 'premiumbilder' in x):
                src = img['src']
                if src.startswith('../premiumbilder/'):
                    src = 'https://momaily.de/' + src[3:]
                elif src.startswith('/premiumbilder/'):
                    src = 'https://momaily.de' + src
                elif src.startswith('premiumbilder/'):
                    src = 'https://momaily.de/' + src
                elif not src.startswith('http'):
                    src = 'https://momaily.de/' + src.lstrip('/')
                parent_td = img.find_parent('td')
                if parent_td:
                    next_td = parent_td.find_next_sibling('td')
                    if next_td:
                        button = next_td.find('input', {'value': 'Absenden'})
                        if button and 'onclick' in button.attrs:
                            onclick = button['onclick']
                            name_match = re.search(r"name=([^'&]+)", onclick)
                            if name_match:
                                photo_name = name_match.group(1)
                                photos.append({
                                    'url': src,
                                    'thumbnail': src,
                                    'name': photo_name,
                                    'border_color': '080'
                                })
        except Exception as e:
            print(f"[DEBUG] Error fetching Momaily photos: {str(e)}")
            import traceback
            print(f"[DEBUG] Full traceback: {traceback.format_exc()}")
    elif project == 'beloops':
        url = f"https://beloops.com/Chat/privat_sendphoto.php?p={p}&id={id_}&action=menu"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        try:
            response = requests.get(url, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            with open('debug_beloops_photos.html', 'w', encoding='utf-8') as f:
                f.write(response.text)
            for img in soup.find_all('img', src=True):
                src = img['src']
                # Sadece profil fotoğraflarını veya özel fotoğrafları filtrele
                if not any(x in src for x in ['privat', 'gallery', 'profile', 'bild']):
                    continue
                # URL düzeltme
                if src.startswith('http'):
                    full_url = src
                elif src.startswith('../privat/'):
                    full_url = f'https://beloops.com/Chat/privat/{src[len("../privat/"):]}'
                elif src.startswith('/privat/'):
                    full_url = f'https://beloops.com{src}'
                elif src.startswith('privat/'):
                    full_url = f'https://beloops.com/Chat/{src}'
                elif src.startswith('http'):
                    full_url = src
                else:
                    full_url = f'https://beloops.com/Chat/{src.lstrip("/")}'
                print("DEBUG PHOTO SRC:", src, "->", full_url)
                # Gönder butonunu bul
                parent_td = img.find_parent('td')
                if parent_td:
                    next_td = parent_td.find_next_sibling('td')
                    if next_td:
                        button = next_td.find('input', {'value': 'Absenden'})
                        if button and 'onclick' in button.attrs:
                            onclick = button['onclick']
                            name_match = re.search(r"name=([^'&]+)", onclick)
                            if name_match:
                                photo_name = name_match.group(1)
                                photos.append({
                                    'url': full_url,
                                    'thumbnail': full_url,
                                    'name': photo_name,
                                    'border_color': '080'
                                })
        except Exception as e:
            print(f"[DEBUG] Error fetching Beloops photos: {str(e)}")
            import traceback
            print(f"[DEBUG] Full traceback: {traceback.format_exc()}")
    
    return render_template('send_photo.html', project=project, p=p, id_=id_, photos=photos)

# Veritabanı başlangıç verilerini oluştur
def init_db():
    with app.app_context():
        db.create_all()
        
        # Projeleri oluştur
        projects = ['momaily', 'liebesfun', 'beloops']
        for project_name in projects:
            if not Project.query.filter_by(name=project_name).first():
                project = Project(name=project_name)
                db.session.add(project)
        
        db.session.commit()
        
        # Admin kullanıcısı yoksa oluştur
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')  # Şifreyi değiştirmeyi unutma!
            db.session.add(admin)
            db.session.commit()
            print("Admin kullanıcısı oluşturuldu!")

@app.route('/accept_friend_request/<p>/<id_>', methods=['POST'])
@login_required
def accept_friend_request(p, id_):
    phpessid = current_user.momaily_phpessid
    if not phpessid:
        flash('Oturum bulunamadı!', 'error')
        return redirect(url_for('chat', project='momaily', p=p, id_=id_))
    # Gerekli parametreleri al
    action = request.form.get('action', 'p_postfach.php')
    data = {k: v for k, v in request.form.items() if k != 'action'}
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        url = f'https://momaily.de/crazy_flirt/{action}'
        resp = requests.post(url, headers=headers, data=data, verify=False)
        if resp.status_code == 200:
            flash('Arkadaşlık isteği kabul edildi!', 'success')
        else:
            flash('Arkadaşlık isteği kabul edilemedi!', 'error')
    except Exception as e:
        flash(f'Hata: {e}', 'error')
    return redirect(url_for('chat', project='momaily', p=p, id_=id_))

@app.route('/reject_friend_request/<p>/<id_>', methods=['POST'])
@login_required
def reject_friend_request(p, id_):
    phpessid = current_user.momaily_phpessid
    if not phpessid:
        flash('Oturum bulunamadı!', 'error')
        return redirect(url_for('chat', project='momaily', p=p, id_=id_))
    action = request.form.get('action', 'p_meinefreunde.php')
    data = {k: v for k, v in request.form.items() if k != 'action'}
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        url = f'https://momaily.de/crazy_flirt/{action}'
        resp = requests.post(url, headers=headers, data=data, verify=False)
        if resp.status_code == 200:
            flash('Arkadaşlık isteği reddedildi!', 'success')
        else:
            flash('Arkadaşlık isteği reddedilemedi!', 'error')
    except Exception as e:
        flash(f'Hata: {e}', 'error')
    return redirect(url_for('chat', project='momaily', p=p, id_=id_))

def fetch_all_beloops_messages(phpessid, p, id_):
    """Tüm Beloops mesajlarını getir"""
    all_messages = []
    start = 0
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            messages, error = fetch_beloops_messages_ajax(phpessid, p, id_, start)
            if error:
                print(f"[DEBUG] Error fetching Beloops messages: {error}")
                retry_count += 1
                time.sleep(1)  # 1 saniye bekle
                continue
                
            if not messages:
                break
                
            all_messages.extend(messages)
            
            if len(messages) < 10:  # 10'dan azsa son sayfa
                break
                
            start += len(messages)
            retry_count = 0  # Başarılı olunca retry sayacını sıfırla
            
        except Exception as e:
            print(f"[DEBUG] Exception in fetch_all_beloops_messages: {str(e)}")
            retry_count += 1
            time.sleep(1)  # 1 saniye bekle
            continue
    
    print(f"[DEBUG] Total Beloops messages fetched: {len(all_messages)}")
    return all_messages

@app.route('/profile/<project>', methods=['GET', 'POST'])
@login_required
def profile_edit(project):
    project = project.lower()
    if project not in ['momaily', 'liebesfun', 'beloops']:
        flash('Geçersiz proje!', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Get user's PHPESSID for the project
    phpessid = None
    if project == 'momaily':
        phpessid = current_user.momaily_phpessid
    elif project == 'liebesfun':
        phpessid = current_user.liebesfun_phpessid
    elif project == 'beloops':
        phpessid = current_user.beloops_phpessid
    
    if not phpessid:
        flash('Oturum bulunamadı! Lütfen ayarlardan oturum bilgilerinizi güncelleyin.', 'error')
        return redirect(url_for('settings'))
    
    # Handle form submission
    if request.method == 'POST':
        success = False
        if project == 'momaily':
            url = "https://momaily.de/crazy_flirt/p_profilpflege.php"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
                'Cookie': f'PHPSESSID={phpessid}'
            }
            try:
                # Get the form data
                data = {
                    'name': request.form.get('name', ''),
                    'age': request.form.get('age', ''),
                    'city': request.form.get('city', ''),
                    'job': request.form.get('job', ''),
                    'working_hours': request.form.get('working_hours', ''),
                    'status': request.form.get('status', ''),
                    'description': request.form.get('description', ''),
                    'submit': 'Speichern'  # Save button text
                }
                
                # Send the form
                response = requests.post(url, headers=headers, data=data, verify=False)
                success = response.status_code == 200
                
                if success:
                    flash('Profil başarıyla güncellendi!', 'success')
                else:
                    flash('Profil güncellenirken bir hata oluştu!', 'error')
                    
            except Exception as e:
                print(f"[DEBUG] Error updating Momaily profile: {str(e)}")
                flash('Profil güncellenirken bir hata oluştu!', 'error')
        
        if success:
            return redirect(url_for('profile_edit', project=project))
    
    # Fetch current profile data
    profile_data = {
        'name': '',
        'age': '',
        'city': '',
        'job': '',
        'working_hours': '',
        'status': '',
        'description': '',
        'photos': []
    }
    
    if project == 'momaily':
        url = "https://momaily.de/crazy_flirt/p_profilpflege.php"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        try:
            response = requests.get(url, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Save response for debugging
            with open('debug_momaily_profile.html', 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Find the form
            form = soup.find('form')
            if form:
                # Get current values from form
                profile_data['name'] = form.find('input', {'name': 'name'}).get('value', '')
                profile_data['age'] = form.find('input', {'name': 'age'}).get('value', '')
                profile_data['city'] = form.find('input', {'name': 'city'}).get('value', '')
                profile_data['job'] = form.find('input', {'name': 'job'}).get('value', '')
                profile_data['working_hours'] = form.find('input', {'name': 'working_hours'}).get('value', '')
                profile_data['status'] = form.find('input', {'name': 'status'}).get('value', '')
                profile_data['description'] = form.find('textarea', {'name': 'description'}).get_text(strip=True)
            
            # Get profile photos
            for img in soup.find_all('img', src=lambda x: x and 'profilbilder' in x):
                src = img['src']
                if src.startswith('../profilbilder/'):
                    src = 'https://momaily.de/' + src[3:]
                elif src.startswith('/profilbilder/'):
                    src = 'https://momaily.de' + src
                elif src.startswith('profilbilder/'):
                    src = 'https://momaily.de/' + src
                elif not src.startswith('http'):
                    src = 'https://momaily.de/' + src.lstrip('/')
                profile_data['photos'].append(src)
            
        except Exception as e:
            print(f"[DEBUG] Error fetching Momaily profile: {str(e)}")
            flash('Profil bilgileri alınırken bir hata oluştu!', 'error')
    
    return render_template('profile_edit.html', project=project, profile=profile_data)

# Profil bilgileri modeli (her müşteri-fake/proje için)
class ProfileInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project = db.Column(db.String(50), nullable=False)
    p = db.Column(db.String(50), nullable=False)  # fake id
    id_ = db.Column(db.String(50), nullable=False)  # müşteri id
    type = db.Column(db.String(20), nullable=False)  # 'customer' veya 'fake'
    name = db.Column(db.String(120), default='')
    city = db.Column(db.String(120), default='')
    job = db.Column(db.String(120), default='')
    working_hours = db.Column(db.String(120), default='')
    status = db.Column(db.String(120), default='')
    updated_at = db.Column(db.DateTime, default=dt.now, onupdate=dt.now)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'project', 'p', 'id_', 'type', name='_profileinfo_uc'),)

# Dialog Info modeli (her müşteri-fake/proje için notlar)
class DialogInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project = db.Column(db.String(50), nullable=False)
    p = db.Column(db.String(50), nullable=False)
    id_ = db.Column(db.String(50), nullable=False)
    info_text = db.Column(db.Text, default='')
    updated_at = db.Column(db.DateTime, default=dt.now, onupdate=dt.now)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'project', 'p', 'id_', name='_dialoginfo_uc'),)

@app.route('/save_profileinfo', methods=['POST'])
@login_required
def save_profileinfo():
    data = request.json
    project = data.get('project')
    p = data.get('p')
    id_ = data.get('id_')
    type_ = data.get('type')  # 'customer' or 'fake'
    name = data.get('name', '')
    city = data.get('city', '')
    job = data.get('job', '')
    working_hours = data.get('working_hours', '')
    status = data.get('status', '')
    if not (project and p and id_ and type_):
        return jsonify({'success': False, 'error': 'Eksik parametre'}), 400
    profile = ProfileInfo.query.filter_by(user_id=current_user.id, project=project, p=p, id_=id_, type=type_).first()
    if not profile:
        profile = ProfileInfo(user_id=current_user.id, project=project, p=p, id_=id_, type=type_)
        db.session.add(profile)
    profile.name = name
    profile.city = city
    profile.job = job
    profile.working_hours = working_hours
    profile.status = status
    db.session.commit()
    return jsonify({'success': True})

@app.route('/save_dialoginfo', methods=['POST'])
@login_required
def save_dialoginfo():
    data = request.json
    project = data.get('project')
    p = data.get('p')
    id_ = data.get('id_')
    info_text = data.get('info_text', '')
    if not (project and p and id_):
        return jsonify({'success': False, 'error': 'Eksik parametre'}), 400
    dialog = DialogInfo.query.filter_by(user_id=current_user.id, project=project, p=p, id_=id_).first()
    if not dialog:
        dialog = DialogInfo(user_id=current_user.id, project=project, p=p, id_=id_)
        db.session.add(dialog)
    dialog.info_text = info_text
    db.session.commit()
    return jsonify({'success': True})

# Kullanıcıya özel takvim etkinlikleri modeli
class UserCalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    event_date = db.Column(db.Date, nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.now)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'event_date', 'note', name='_usercal_uc'),)

@app.route('/calendar/add', methods=['POST'])
@login_required
def add_calendar_event():
    data = request.json
    event_date = data.get('event_date')  # 'YYYY-MM-DD'
    note = data.get('note', '').strip()
    if not event_date or not note:
        return jsonify({'success': False, 'error': 'Tarih ve not zorunlu'}), 400
    try:
        date_obj = datetime.strptime(event_date, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'success': False, 'error': 'Tarih formatı yanlış'}), 400
    event = UserCalendarEvent(user_id=current_user.id, event_date=date_obj, note=note)
    db.session.add(event)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/calendar/events', methods=['GET'])
@login_required
def get_calendar_events():
    # Tüm etkinlikleri veya belirli bir günü döndür
    date_str = request.args.get('date')  # 'YYYY-MM-DD'
    query = UserCalendarEvent.query.filter_by(user_id=current_user.id)
    if date_str:
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
            query = query.filter_by(event_date=date_obj)
        except Exception:
            return jsonify({'success': False, 'error': 'Tarih formatı yanlış'}), 400
    events = query.order_by(desc(UserCalendarEvent.event_date)).all()
    return jsonify({'success': True, 'events': [
        {'date': e.event_date.strftime('%Y-%m-%d'), 'note': e.note} for e in events
    ]})

@app.route('/calendar/update', methods=['POST'])
@login_required
def update_calendar_event():
    data = request.json
    event_id = data.get('id')
    note = data.get('note', '').strip()
    if not event_id or not note:
        return jsonify({'success': False, 'error': 'Eksik parametre'}), 400
    event = UserCalendarEvent.query.filter_by(id=event_id, user_id=current_user.id).first()
    if not event:
        return jsonify({'success': False, 'error': 'Etkinlik bulunamadı'}), 404
    event.note = note
    db.session.commit()
    return jsonify({'success': True})

@app.route('/calendar/delete', methods=['POST'])
@login_required
def delete_calendar_event():
    data = request.json
    event_id = data.get('id')
    if not event_id:
        return jsonify({'success': False, 'error': 'Eksik parametre'}), 400
    event = UserCalendarEvent.query.filter_by(id=event_id, user_id=current_user.id).first()
    if not event:
        return jsonify({'success': False, 'error': 'Etkinlik bulunamadı'}), 404
    db.session.delete(event)
    db.session.commit()
    return jsonify({'success': True})

# Dashboard ve chat route'larına bugünkü olayları ekle
from flask import g

def get_todays_calendar_events(user_id):
    today = datetime.now().date()
    events = UserCalendarEvent.query.filter_by(user_id=user_id, event_date=today).all()
    return [{'id': e.id, 'date': e.event_date.strftime('%Y-%m-%d'), 'note': e.note} for e in events]

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project = db.Column(db.String(50), nullable=False)  # 'momaily', 'liebesfun', 'beloops'
    phpessid = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=dt.now)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'project', 'phpessid', name='_usersession_uc'),)

def send_beloops_message(phpessid, p, id_, message):
    url = f"https://beloops.com/Chat/privat_postfach.php?p={p}&id={id_}&action=send"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': f'https://beloops.com/Chat/privat_postfach.php?p={p}&id={id_}&action=read',
        'Origin': 'https://beloops.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    }
    cookies = {'PHPSESSID': phpessid}
    data = {'inhalt': message}
    try:
        response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)
        print('[DEBUG] Beloops send message status:', response.status_code)
        print('[DEBUG] Beloops send message response:', response.text[:300])
        return response.status_code == 200
    except Exception as e:
        print(f"[DEBUG] Error sending Beloops message: {str(e)}")
        return False

def fetch_project_counts(url, phpsessid, project):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'Cookie': f'PHPSESSID={phpsessid}'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', style=lambda x: x and 'width:250px' in x)
        result = {'dialog': 0, 'asa': 0, 'wartezimmer': 0}
        if table:
            rows = table.find_all('tr')
            for row in rows:
                tds = row.find_all('td')
                if len(tds) == 2:
                    label = tds[0].get_text(strip=True).lower()
                    value = int(tds[1].get_text(strip=True))
                    if 'offenen dialoge' in label:
                        result['dialog'] = value
                    elif 'offene asa' in label:
                        result['asa'] = value
                    elif 'wartezimmer' in label:
                        result['wartezimmer'] = value
        return result
    except Exception as e:
        print(f"[DEBUG] Error fetching {project} counts: {e}")
        return {'dialog': 0, 'asa': 0, 'wartezimmer': 0}

# Cache süresi (saniye)
CACHE_DURATION = 15

# Cache için son güncelleme zamanı
last_cache_time = 0
cached_result = None

@app.route('/api/message_counts')
@login_required
def api_message_counts():
    global last_cache_time, cached_result
    
    # Cache kontrolü
    current_time = time.time()
    if cached_result and (current_time - last_cache_time) < CACHE_DURATION:
        return jsonify(cached_result)
    
    # Her proje için moderatör bazlı sayılar
    result = {}
    
    def fetch_project_data(project):
        project_data = {
            'moderators': [],
            'total': {'dialog': 0, 'asa': 0, 'wartezimmer': 0}
        }
        
        sessions = UserProjectSession.query.filter_by(user_id=current_user.id, project=project).all()
        
        for session in sessions:
            if not session.phpessid:
                continue
                
            if project == 'momaily':
                url = 'https://momaily.de/crazy_flirt/c.php'
            elif project == 'liebesfun':
                url = 'https://liebesfun.de/crazy_flirt/c.php'
            elif project == 'beloops':
                url = 'https://beloops.com/Chat/privat_base.php'
                
            try:
                counts = fetch_project_counts(url, session.phpessid, project)
                project_data['moderators'].append({
                    'moderator_name': session.moderator_name or 'Moderatör',
                    'dialog': counts['dialog'],
                    'asa': counts['asa'],
                    'wartezimmer': counts['wartezimmer']
                })
                project_data['total']['dialog'] += counts['dialog']
                project_data['total']['asa'] += counts['asa']
                project_data['total']['wartezimmer'] += counts['wartezimmer']
            except Exception as e:
                print(f"Error fetching counts for {project}: {str(e)}")
                continue
                
        return project, project_data
    
    # Paralel işleme kaldırıldı, sıralı işleniyor
    for project in ['momaily', 'liebesfun', 'beloops']:
        project, project_data = fetch_project_data(project)
        result[project] = project_data
    
    # Cache'i güncelle
    cached_result = result
    last_cache_time = current_time
    
    return jsonify(result)

class DailyCoinStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    coins = db.Column(db.Integer, default=0)
    messages = db.Column(db.Integer, default=0)
    euro = db.Column(db.Float, default=0.0)
    project = db.Column(db.String(32), default='momaily')  # yeni alan
    created_at = db.Column(db.DateTime, default=dt.now)
    __table_args__ = (db.UniqueConstraint('user_id', 'date', 'project', name='_user_date_project_uc'),)

@app.route('/fetch_momaily_coins')
@login_required
def fetch_momaily_coins():
    phpessid = current_user.momaily_phpessid
    if not phpessid:
        return jsonify({'success': False, 'error': 'Momaily PHPSESSID bulunamadı!'}), 400
    url = 'https://momaily.de/crazy_flirt/view_umsatz2.php'
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code != 200:
            return jsonify({'success': False, 'error': 'Sayfa yüklenemedi!'}), 500
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table', attrs={'cellpadding': '0', 'cellspacing': '0', 'style': 'width:1000px;'})
        if not table:
            return jsonify({'success': False, 'error': 'Tablo bulunamadı!'}), 404
        rows = table.find_all('tr')
        total_coins = 0
        for row in rows:
            tds = row.find_all('td')
            if len(tds) < 11:
                continue
            if 'gesamt' in tds[0].get_text(strip=True).lower():
                try:
                    total_coins = int(tds[7].get_text(strip=True))  # COIN
                except:
                    total_coins = 0
                total_messages = total_coins // 10  # 1 mesaj = 10 coin
                euro = round(total_messages * 0.15, 2)
                break
        date_obj = germany_now().date()
        # Veritabanına kaydet
        stat = DailyCoinStats.query.filter_by(user_id=current_user.id, date=date_obj).first()
        if not stat:
            stat = DailyCoinStats(user_id=current_user.id, date=date_obj)
            db.session.add(stat)
        stat.coins = total_coins
        stat.messages = total_messages
        stat.euro = euro
        db.session.commit()
        return jsonify({'success': True, 'date': str(date_obj), 'coins': total_coins, 'messages': total_messages, 'euro': euro})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/fetch_momaily_coins_all')
@login_required
def fetch_momaily_coins_all():
    phpessid = current_user.momaily_phpessid
    if not phpessid:
        return jsonify({'success': False, 'error': 'Momaily PHPSESSID bulunamadı!'}), 400
    today = germany_now().date()
    year = today.year
    month = today.month
    results = []
    for day in range(1, today.day + 1):
        url = f'https://momaily.de/crazy_flirt/view_umsatz2.php?s_t={day:02d}&s_m={month:02d}&s_j={year}&e_t={day:02d}&e_m={month:02d}&e_j={year}'
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Cookie': f'PHPSESSID={phpessid}'
        }
        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(url, headers=headers, verify=False)
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.text, 'html.parser')
            table = soup.find('table', attrs={'cellpadding': '0', 'cellspacing': '0', 'style': 'width:1000px;'})
            if not table:
                continue
            rows = table.find_all('tr')
            total_coins = 0
            for row in rows:
                tds = row.find_all('td')
                if len(tds) < 11:
                    continue
                if 'gesamt' in tds[0].get_text(strip=True).lower():
                    try:
                        total_coins = int(tds[7].get_text(strip=True))  # COIN
                    except:
                        total_coins = 0
                    total_messages = total_coins // 10  # 1 mesaj = 10 coin
                    euro = round(total_messages * 0.15, 2)
                    break
                try:
                    coins = int(tds[10].get_text(strip=True))
                except:
                    continue
                total_coins += coins
            date_obj = datetime(year, month, day).date()
            messages = total_coins // 10
            euro = round(messages * 0.15, 2)
            # Veritabanına kaydet
            stat = DailyCoinStats.query.filter_by(user_id=current_user.id, date=date_obj).first()
            if not stat:
                stat = DailyCoinStats(user_id=current_user.id, date=date_obj)
                db.session.add(stat)
            stat.coins = total_coins
            stat.messages = messages
            stat.euro = euro
            results.append({'date': str(date_obj), 'coins': total_coins, 'messages': messages, 'euro': euro})
        except Exception as e:
            continue
    db.session.commit()
    return jsonify({'success': True, 'results': results})

def fetch_all_project_data():
    """Tüm projelerin verilerini çek"""
    with app.app_context():
        users = User.query.all()
        for user in users:
            # Momaily verilerini çek
            if user.momaily_phpessid:
                try:
                    url = 'https://momaily.de/crazy_flirt/view_umsatz2.php'
                    headers = {
                        'User-Agent': 'Mozilla/5.0',
                        'Cookie': f'PHPSESSID={user.momaily_phpessid}'
                    }
                    resp = requests.get(url, headers=headers, verify=False)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        table = soup.find('table', attrs={'cellpadding': '0', 'cellspacing': '0', 'style': 'width:1000px;'})
                        if table:
                            rows = table.find_all('tr')
                            total_coins = 0
                            for row in rows:
                                tds = row.find_all('td')
                                if len(tds) < 11:
                                    continue
                                if 'gesamt' in tds[0].get_text(strip=True).lower():
                                    try:
                                        total_coins = int(tds[7].get_text(strip=True))  # COIN
                                    except:
                                        total_coins = 0
                                    total_messages = total_coins // 10  # 1 mesaj = 10 coin
                                    euro = round(total_messages * 0.15, 2)
                                    break
                                try:
                                    coins = int(tds[10].get_text(strip=True))
                                except:
                                    continue
                                total_coins += coins
                            date_obj = germany_now().date()
                            messages = total_coins // 10
                            euro = round(messages * 0.15, 2)
                            
                            # Veritabanına kaydet
                            stat = DailyCoinStats.query.filter_by(
                                user_id=user.id, 
                                date=date_obj,
                                project='momaily'
                            ).first()
                            if not stat:
                                stat = DailyCoinStats(
                                    user_id=user.id, 
                                    date=date_obj,
                                    project='momaily'
                                )
                                db.session.add(stat)
                            stat.coins = total_coins
                            stat.messages = messages
                            stat.euro = euro
                            db.session.commit()
                except Exception as e:
                    print(f"Momaily veri çekme hatası: {str(e)}")

            # Liebesfun verilerini çek
            if user.liebesfun_phpessid:
                try:
                    url = 'https://liebesfun.de/crazy_flirt/view_umsatz2.php'
                    headers = {
                        'User-Agent': 'Mozilla/5.0',
                        'Cookie': f'PHPSESSID={user.liebesfun_phpessid}'
                    }
                    resp = requests.get(url, headers=headers, verify=False)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        table = soup.find('table', attrs={'cellpadding': '0', 'cellspacing': '0', 'style': 'width:1000px;'})
                        if table:
                            rows = table.find_all('tr')
                            total_coins = 0
                            for row in rows:
                                tds = row.find_all('td')
                                if len(tds) < 11:
                                    continue
                                if 'gesamt' in tds[0].get_text(strip=True).lower():
                                    try:
                                        total_coins = int(tds[7].get_text(strip=True))  # COIN
                                    except:
                                        total_coins = 0
                                    total_messages = total_coins // 10  # 1 mesaj = 10 coin
                                    euro = round(total_messages * 0.15, 2)
                                    break
                                try:
                                    coins = int(tds[10].get_text(strip=True))
                                except:
                                    continue
                                total_coins += coins
                            date_obj = germany_now().date()
                            messages = total_coins // 10
                            euro = round(messages * 0.15, 2)
                            
                            # Veritabanına kaydet
                            stat = DailyCoinStats.query.filter_by(
                                user_id=user.id, 
                                date=date_obj,
                                project='liebesfun'
                            ).first()
                            if not stat:
                                stat = DailyCoinStats(
                                    user_id=user.id, 
                                    date=date_obj,
                                    project='liebesfun'
                                )
                                db.session.add(stat)
                            stat.coins = total_coins
                            stat.messages = messages
                            stat.euro = euro
                            db.session.commit()
                except Exception as e:
                    print(f"Liebesfun veri çekme hatası: {str(e)}")

def run_scheduler():
    """Zamanlayıcıyı çalıştır"""
    while True:
        schedule.run_pending()
        time.sleep(60)

# Zamanlayıcıyı ayarla
schedule.every(1).hours.do(fetch_all_project_data)

# Zamanlayıcıyı arka planda başlat
scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.daemon = True
scheduler_thread.start()

# --- Almanya saatine göre tarih fonksiyonu ---
def germany_now():
    return datetime.now(ZoneInfo("Europe/Berlin"))

@app.route('/fetch_beloops_coins')
@login_required
def fetch_beloops_coins():
    phpessid = current_user.beloops_phpessid
    if not phpessid:
        return jsonify({'success': False, 'error': 'Beloops PHPSESSID bulunamadı!'}), 400
    url = 'https://beloops.com/Chat/privat_umsatz.php'
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code != 200:
            return jsonify({'success': False, 'error': 'Sayfa yüklenemedi!'}), 500
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table', attrs={'cellpadding': '0', 'cellspacing': '0', 'style': 'width:100%;'})
        if not table:
            return jsonify({'success': False, 'error': 'Tablo bulunamadı!'}), 404
        rows = table.find_all('tr')
        total_coins = 0
        total_messages = 0
        for row in rows:
            tds = row.find_all('td')
            if len(tds) < 5:
                continue
            if 'gesamt' in tds[0].get_text(strip=True).lower():
                try:
                    total_messages = int(tds[1].get_text(strip=True))  # PM
                except:
                    total_messages = 0
                try:
                    total_coins = int(tds[5].get_text(strip=True))     # COIN
                except:
                    total_coins = 0
                break
        euro = round(total_messages * 0.15, 2)
        date_obj = germany_now().date()
        # Veritabanına kaydet
        stat = DailyCoinStats.query.filter_by(user_id=current_user.id, date=date_obj, project='beloops').first()
        if not stat:
            stat = DailyCoinStats(user_id=current_user.id, date=date_obj, project='beloops')
            db.session.add(stat)
        stat.coins = total_coins
        stat.messages = total_messages
        stat.euro = euro
        db.session.commit()
        return jsonify({'success': True, 'date': str(date_obj), 'coins': total_coins, 'messages': total_messages, 'euro': euro})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/fetch_liebesfun_coins')
@login_required
def fetch_liebesfun_coins():
    phpessid = current_user.liebesfun_phpessid
    if not phpessid:
        return jsonify({'success': False, 'error': 'Liebesfun PHPSESSID bulunamadı!'}), 400
    
    # Bugünün tarihini al
    today = germany_now().date()
    # Dünün tarihini al
    yesterday = today - timedelta(days=1)
    
    # Önce bugünün verilerini dene
    url = f'https://liebesfun.de/crazy_flirt/view_umsatz2.php?s_t={today.day:02d}&s_m={today.month:02d}&s_j={today.year}&e_t={today.day:02d}&e_m={today.month:02d}&e_j={today.year}'
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': f'PHPSESSID={phpessid}'
    }
    
    try:
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, headers=headers, verify=False)
        
        # Eğer bugün veri yoksa dünün verilerini dene
        if resp.status_code != 200 or 'Tablo bulunamadı' in resp.text:
            url = f'https://liebesfun.de/crazy_flirt/view_umsatz2.php?s_t={yesterday.day:02d}&s_m={yesterday.month:02d}&s_j={yesterday.year}&e_t={yesterday.day:02d}&e_m={yesterday.month:02d}&e_j={yesterday.year}'
            resp = requests.get(url, headers=headers, verify=False)
            date_obj = yesterday
        else:
            date_obj = today
            
        if resp.status_code != 200:
            return jsonify({'success': False, 'error': 'Sayfa yüklenemedi!'}), 500
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Tüm tabloları kontrol et
        tables = soup.find_all('table')
        target_table = None
        
        for table in tables:
            # Tablo içinde "gesamt" kelimesini ara
            if table.find(string=lambda text: text and 'gesamt' in text.lower()):
                target_table = table
                break
        
        if not target_table:
            return jsonify({'success': False, 'error': 'Tablo bulunamadı!'}), 404
            
        rows = target_table.find_all('tr')
        total_coins = 0
        
        for row in rows:
            tds = row.find_all('td')
            if len(tds) < 5:
                continue
            if 'gesamt' in row.get_text(strip=True).lower():
                try:
                    # Tüm hücreleri kontrol et
                    for td in tds:
                        text = td.get_text(strip=True)
                        if text.isdigit():
                            total_coins = int(text)
                            break
                except:
                    pass
                break
        
        # 10 coin = 1 mesaj
        total_messages = total_coins // 10
        # 1 mesaj = 0.15€
        euro = round(total_messages * 0.15, 2)
        
        # Veritabanına kaydet
        stat = DailyCoinStats.query.filter_by(user_id=current_user.id, date=date_obj, project='liebesfun').first()
        if not stat:
            stat = DailyCoinStats(user_id=current_user.id, date=date_obj, project='liebesfun')
            db.session.add(stat)
        stat.coins = total_coins
        stat.messages = total_messages
        stat.euro = euro
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'date': str(date_obj), 
            'coins': total_coins, 
            'messages': total_messages, 
            'euro': euro
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

class UserProjectSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 'user' yerine 'users' kullan
    project = db.Column(db.String(50), nullable=False)  # 'momaily', 'liebesfun', 'beloops'
    phpessid = db.Column(db.String(255), nullable=False)
    moderator_name = db.Column(db.String(120), nullable=True)  # Yeni eklendi
    created_at = db.Column(db.DateTime, default=dt.now)

    user = db.relationship('User', backref='project_sessions')

@app.route('/add_phpessid', methods=['POST'])
@login_required
def add_phpessid():
    project = request.form.get('project')
    phpessid = request.form.get('phpessid')
    moderator_name = request.form.get('moderator_name')
    print("DEBUG: add_phpessid", project, phpessid, moderator_name, current_user.id)
    if not project or not phpessid or not moderator_name:
        flash('Eksik bilgi!', 'error')
        return redirect(url_for('settings'))
    # Aynı PHPESSID tekrar eklenmesin
    exists = UserProjectSession.query.filter_by(user_id=current_user.id, project=project, phpessid=phpessid).first()
    if exists:
        flash('Bu PHPESSID zaten ekli!', 'warning')
        return redirect(url_for('settings'))
    session = UserProjectSession(user_id=current_user.id, project=project, phpessid=phpessid, moderator_name=moderator_name)
    db.session.add(session)
    db.session.commit()
    flash('PHPESSID eklendi!', 'success')
    print("DEBUG: PHPESSID EKLENİYOR", project, phpessid, moderator_name, current_user.id)
    return redirect(url_for('settings'))

# Yardımcı fonksiyon: aktif PHPESSID getir

def get_active_phpessid(user, project):
    session = UserProjectSession.query.filter_by(user_id=user.id, project=project).order_by(UserProjectSession.created_at.desc()).first()
    return session.phpessid if session else None

@app.route('/delete_phpessid', methods=['POST'])
@login_required
def delete_phpessid():
    session_id = request.form.get('session_id')
    session = UserProjectSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        flash('Kayıt bulunamadı!', 'error')
        return redirect(url_for('settings'))
    db.session.delete(session)
    db.session.commit()
    flash('PHPESSID silindi!', 'success')
    return redirect(url_for('settings'))

@app.route('/api/first_conversation')
@login_required
def api_first_conversation():
    project = request.args.get('project')
    moderator_name = request.args.get('moderator_name')
    
    if not project or not moderator_name:
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400
    
    # Cache kontrolü
    cache_key = f"{project}_{moderator_name}"
    current_time = time.time()
    
    if cache_key in conversation_cache and (current_time - last_conversation_cache_time.get(cache_key, 0)) < CACHE_DURATION:
        return jsonify(conversation_cache[cache_key])
    
    # Moderatörün PHPESSID'sini bul
    session = UserProjectSession.query.filter_by(
        user_id=current_user.id,
        project=project,
        moderator_name=moderator_name
    ).first()
    
    if not session or not session.phpessid:
        return jsonify({'success': False, 'error': 'Moderator not found'}), 404
    
    try:
        # Projeye göre ilk sohbeti bul
        if project == 'momaily':
            conversations = fetch_momaily_conversations(session.phpessid)
        elif project == 'liebesfun':
            conversations = fetch_liebesfun_conversations(session.phpessid)
        elif project == 'beloops':
            conversations = fetch_beloops_conversations(session.phpessid)
        else:
            return jsonify({'success': False, 'error': 'Invalid project'}), 400
        
        if conversations:
            result = {
                'success': True,
                'p': conversations[0]['p'],
                'id_': conversations[0]['id'],
                'phpessid': session.phpessid
            }
            
            # Cache'e kaydet
            conversation_cache[cache_key] = result
            last_conversation_cache_time[cache_key] = current_time
            
            return jsonify(result)
        else:
            return jsonify({'success': False, 'error': 'No active conversations'}), 404
            
    except Exception as e:
        print(f"Error fetching first conversation: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Conversation cache for /api/first_conversation ---
conversation_cache = {}
last_conversation_cache_time = {}


# --- Momaily Admin PHPSESSID Settings Page (admin only) ---
@app.route('/admin/momaily_admin_session', methods=['GET', 'POST'])
@login_required
def momaily_admin_session():
    if not current_user.is_admin:
        return 'Unauthorized', 403
    session = MomailyAdminSession.query.order_by(MomailyAdminSession.created_at.desc()).first()
    if request.method == 'POST':
        phpessid = request.form.get('phpessid')
        if phpessid:
            new_session = MomailyAdminSession(phpessid=phpessid)
            db.session.add(new_session)
            db.session.commit()
            flash('Momaily admin PHPSESSID kaydedildi!', 'success')
            return redirect(url_for('momaily_admin_session'))
    return render_template('admin_momaily_admin_session.html', session=session)

# --- Momaily Toplist API (with PHPSESSID) ---
@app.route('/api/toplist/momaily')
@login_required
def api_toplist_momaily():
    """
    Fetch and parse the Momaily global top 10 list (today, yesterday, day before yesterday)
    from https://momaily.de/AxAdmin/kickit_v3.php using stored PHPSESSID and return as JSON.
    """
    MOMAILY_ADMIN_URL = 'https://momaily.de/AxAdmin/kickit_v3.php'
    session = MomailyAdminSession.query.order_by(MomailyAdminSession.created_at.desc()).first()
    if not session or not session.phpessid:
        return jsonify({'success': False, 'error': 'Momaily admin PHPSESSID ayarlardan girilmemiş!'}), 400
    cookies = {'PHPSESSID': session.phpessid}
    try:
        resp = requests.get(MOMAILY_ADMIN_URL, cookies=cookies, timeout=10, verify=False)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        tables = soup.select('table[style="width:250px;"]')
        result = {}
        labels = ['today', 'yesterday', 'day_before']
        for idx, label in enumerate(labels):
            if idx >= len(tables):
                result[label] = []
                continue
            table = tables[idx]
            rows = table.find_all('tr')[1:]  # skip header
            toplist = []
            for i in range(0, len(rows), 1):
                tds = rows[i].find_all('td')
                if len(tds) != 2:
                    continue
                img = tds[0].find('img')
                if img:
                    trophy = img['src']
                else:
                    trophy = None
                info = tds[1].find_all('span')
                if len(info) >= 3:
                    username = info[0].get_text(strip=True)
                    agency = info[1].get_text(strip=True)
                    coins = info[2].get_text(strip=True)
                else:
                    username = tds[1].get_text(strip=True)
                    agency = ''
                    coins = ''
                toplist.append({
                    'rank': len(toplist)+1,
                    'username': username,
                    'agency': agency,
                    'coins': f"{coins} Coins",
                    'trophy': trophy
                })
            result[label] = toplist
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add MomailyAdminSession model with the other models
class MomailyAdminSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phpessid = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.now)

def parse_top_chatter_heute(html):
    soup = BeautifulSoup(html, 'html.parser')
    # Tüm tabloları gez
    for table in soup.find_all('table', style="width:250px;"):
        # Başlıkta "TOP Chatter Heute" geçen tabloyu bul
        header = table.find('span', class_='titel s18')
        if header and 'TOP Chatter Heute' in header.text:
            rows = table.find_all('tr')[1:]  # ilk satır başlık
            result = []
            for i, row in enumerate(rows):
                tds = row.find_all('td')
                if len(tds) < 2:
                    continue
                # Kupa resmi
                trophy_img = tds[0].find('img')
                trophy = trophy_img['src'] if trophy_img else None
                # Kullanıcı adı ve ajans
                spans = tds[1].find_all('span')
                username = spans[0].text.strip() if len(spans) > 0 else ''
                agency = spans[1].text.strip() if len(spans) > 1 else ''
                coins = spans[-1].text.strip() if spans else ''
                result.append({
                    'rank': i+1,
                    'trophy': trophy,
                    'username': username,
                    'agency': agency,
                    'coins': f"{coins} Coins"
                })
            return result
    return []

import requests
from bs4 import BeautifulSoup

def fetch_liebesfun_top10():
    url = "https://liebesfun.de/A_center/kickit_v3.php"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    table = soup.find("table")
    rows = table.find_all("tr")[2:]  # İlk iki satır başlık ve başlık altı

    result = []
    for i, row in enumerate(rows, 1):
        tds = row.find_all("td")
        if len(tds) != 2:
            continue
        # Sıra veya kupa
        left = tds[0]
        trophy_img = left.find("img")
        if trophy_img:
            trophy = trophy_img["src"]
            rank = i
        else:
            trophy = None
            rank = int(left.text.strip())
        # Kullanıcı adı ve coin
        right = tds[1]
        username = right.find("span", style=lambda s: s and "font-weight:bold;" in s).text.strip()
        coins_text = right.find_all("span")[-1].text
        coins = int(coins_text.replace("Coins", "").strip())
        result.append({
            "rank": rank,
            "trophy": trophy,
            "username": username,
            "coins": f"{coins} Coins"
        })
    return result

# print(fetch_liebesfun_top10())

class LiebesfunAdminSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phpessid = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.now)

@app.route('/api/toplist/liebesfun')
@login_required
def api_toplist_liebesfun():
    LIEBESFUN_ADMIN_URL = 'https://liebesfun.de/A_center/kickit_v3.php'
    session = LiebesfunAdminSession.query.order_by(LiebesfunAdminSession.created_at.desc()).first()
    if not session or not session.phpessid:
        return jsonify({'success': False, 'error': 'Liebesfun admin PHPSESSID ayarlardan girilmemiş!'}), 400
    try:
        headers = {
            'Cookie': f'PHPSESSID={session.phpessid}',
            'User-Agent': 'Mozilla/5.0'
        }
        response = requests.get(LIEBESFUN_ADMIN_URL, headers=headers)
        if response.status_code != 200:
            return jsonify({'success': False, 'error': 'Failed to fetch Liebesfun data'}), 500
        soup = BeautifulSoup(response.text, 'html.parser')
        # Sadece "TOP Chatter Heute" başlıklı tabloyu bul
        table = None
        for t in soup.find_all('table', style="width:250px;"):
            header = t.find('span', class_='titel s18')
            if header and 'Heute' in header.text:
                table = t
                break
        if not table:
            return jsonify({'success': False, 'error': 'No data found'}), 404
        rows = table.find_all('tr')[1:]  # ilk satır başlık
        result = []
        for row in rows:
            cols = row.find_all('td')
            if len(cols) != 2:
                continue
            left_col = cols[0]
            trophy_img = left_col.find('img')
            if trophy_img:
                trophy = trophy_img['src']
                rank = len(result) + 1
            else:
                trophy = None
                rank = int(left_col.text.strip().replace('.', ''))
            right_col = cols[1]
            username = right_col.find('span', style=lambda s: s and 'font-weight:bold' in s).text.strip()
            coins_text = right_col.find_all('span')[-1].text
            coins = int(coins_text.replace('Coins', '').strip())
            result.append({
                'rank': rank,
                'trophy': trophy,
                'username': username,
                'coins': f"{coins} Coins"
            })
        return jsonify({
            'success': True,
            'data': {
                'today': result
            }
        })
    except Exception as e:
        print(f"Error fetching Liebesfun toplist: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/liebesfun_admin_session', methods=['GET', 'POST'])
@login_required
def liebesfun_admin_session():
    if not current_user.is_admin:
        return 'Unauthorized', 403
        
    session = LiebesfunAdminSession.query.order_by(LiebesfunAdminSession.created_at.desc()).first()
    
    if request.method == 'POST':
        phpessid = request.form.get('phpessid')
        if phpessid:
            new_session = LiebesfunAdminSession(phpessid=phpessid)
            db.session.add(new_session)
            db.session.commit()
            flash('Liebesfun admin PHPSESSID kaydedildi!', 'success')
            return redirect(url_for('liebesfun_admin_session'))
            
    return render_template('admin_liebesfun_admin_session.html', session=session)

class BeloopsAdminSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phpessid = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.now)

@app.route('/api/toplist/beloops')
@login_required
def api_toplist_beloops():
    """
    Fetch and parse the Beloops global top 10 list (today only)
    from https://beloops.com/Admin/kickit_v3.php using stored PHPSESSID and return as JSON.
    """
    BELOOPS_ADMIN_URL = 'https://beloops.com/Admin/kickit_v3.php'
    session = BeloopsAdminSession.query.order_by(BeloopsAdminSession.created_at.desc()).first()
    if not session or not session.phpessid:
        return jsonify({'success': False, 'error': 'Beloops admin PHPSESSID ayarlardan girilmemiş!'}), 400
    try:
        headers = {
            'Cookie': f'PHPSESSID={session.phpessid}',
            'User-Agent': 'Mozilla/5.0'
        }
        response = requests.get(BELOOPS_ADMIN_URL, headers=headers)
        if response.status_code != 200:
            return jsonify({'success': False, 'error': 'Failed to fetch Beloops data'}), 500
        soup = BeautifulSoup(response.text, 'html.parser')
        # Sadece "TOP Chatter Heute" başlıklı tabloyu bul
        table = None
        for t in soup.find_all('table', style=lambda s: s and 'width:95%' in s):
            header = t.find('h3')
            if header and 'Heute' in header.text:
                table = t
                break
        if not table:
            return jsonify({'success': False, 'error': 'No data found'}), 404
        rows = table.find_all('tr')[1:]  # ilk satır başlık
        trophy_paths = [
            "../pic/pokal_chat_gold.png",
            "../pic/pokal_chat_silber.png",
            "../pic/pokal_chat_bronze.png"
        ]
        result = []
        for idx, row in enumerate(rows):
            cols = row.find_all('td')
            if len(cols) != 2:
                continue
            # Sıra numarası
            left_col = cols[0]
            rank = int(left_col.get_text(strip=True).replace('.', ''))
            # Kullanıcı adı ve coin
            right_col = cols[1]
            username = right_col.find('span', style=lambda s: s and 'font-weight:bold' in s).text.strip()
            coins_text = right_col.find_all('span')[-1].text
            coins = int(coins_text.replace('Coins', '').strip())
            trophy = trophy_paths[idx] if idx < 3 else None
            result.append({
                'rank': rank,
                'trophy': trophy,
                'username': username,
                'coins': f"{coins} Coins"
            })
        return jsonify({
            'success': True,
            'data': {
                'today': result
            }
        })
    except Exception as e:
        print(f"Error fetching Beloops toplist: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/beloops_admin_session', methods=['GET', 'POST'])
@login_required
def beloops_admin_session():
    if not current_user.is_admin:
        return 'Unauthorized', 403
    session = BeloopsAdminSession.query.order_by(BeloopsAdminSession.created_at.desc()).first()
    if request.method == 'POST':
        phpessid = request.form.get('phpessid')
        if phpessid:
            new_session = BeloopsAdminSession(phpessid=phpessid)
            db.session.add(new_session)
            db.session.commit()
            flash('Beloops admin PHPSESSID kaydedildi!', 'success')
            return redirect(url_for('beloops_admin_session'))
    return render_template('admin_beloops_admin_session.html', session=session)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 