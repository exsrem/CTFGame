from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_PERMANENT'] = False  # Oturum kalıcı değil
db = SQLAlchemy(app)

# Kullanıcı modeli
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Integer, default=0)
    solved_flags = db.relationship('Flag', secondary='user_flags')
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime, default=datetime.utcnow)

# Flagler
class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True)
    correct_flag = db.Column(db.String(200))

# Kullanıcı ve Flag arasındaki ilişkiyi tanımlıyoruz
class UserFlags(db.Model):
    __tablename__ = 'user_flags'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    flag_id = db.Column(db.Integer, db.ForeignKey('flag.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Flag'lerin listesi
FLAGS = {
    "bjk.png": "FLAG{BESIKTAS}",
    "CZgroup.jpg": "FLAG{CZEROLAK}",
    "fener.png": "FLAG{FENERBAHCE}",
    "galatasaray.jpeg": "FLAG{GALATASARAY}",
}

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Hatalı giriş sayısı kontrolü
        if user:
            if user.failed_attempts >= 3 and datetime.utcnow() - user.last_failed_attempt < timedelta(minutes=5):
                flash('Hesabınız kilitlendi. Lütfen birkaç dakika sonra tekrar deneyin.', 'danger')
                return render_template('login.html')

            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                user.failed_attempts = 0  # Başarılı giriş sonrası başarısız denemeleri sıfırla
                db.session.commit()
                return redirect(url_for('home'))
            else:
                user.failed_attempts += 1
                user.last_failed_attempt = datetime.utcnow()
                db.session.commit()
                flash('Hatalı kullanıcı adı veya şifre!', 'danger')

        else:
            flash('Kullanıcı adı bulunamadı!', 'danger')
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten alınmış!', 'danger')
        else:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            flash('Başarıyla kayıt oldunuz, giriş yapabilirsiniz!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/scoreboard')
def scoreboard():
    users = User.query.order_by(User.score.desc()).all()
    return render_template('scoreboard.html', users=users)
    

@app.route('/level/<int:level>', methods=['GET', 'POST'])
def level(level):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    images = list(FLAGS.keys())
    if level < 1 or level > len(images):
        return redirect(url_for('home'))
    
    user = User.query.get(session['user_id'])
    image = images[level - 1]
    flag_correct = False
    
    if request.method == 'POST':
        submitted_flag = request.form['flag']
        if submitted_flag == FLAGS[image]:
            if not any(f.flag.name == image for f in user.solved_flags):
                user.score += 10
                flag = Flag.query.filter_by(name=image).first()
                if flag:
                    user.solved_flags.append(flag)
                db.session.commit()
            flash('Tebrikler! 🎉👏', 'success')
            flag_correct = True
        else:
            flash('Yanlış flag, tekrar dene!', 'danger')
    
    # solved_flags None olursa boş bir liste olarak işleme
    if user.solved_flags is None:
        user.solved_flags = []

    return render_template('level.html', level=level, image=image, flag_correct=flag_correct)

@app.route('/download/<image>')
def download(image):
    image_path = os.path.join('static', image)
    return send_file(image_path, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        # Veritabanı tablolarını sıfırlayın
        db.drop_all()
        db.create_all()
        # Flag'leri yalnızca bir kez ekleyin
        if not Flag.query.first():
            for name, correct_flag in FLAGS.items():
                flag = Flag(name=name, correct_flag=correct_flag)
                db.session.add(flag)
            db.session.commit()
    app.run(debug=True)
