from flask import Flask, render_template, url_for , request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/breakfast.db'
app.config['SQLALCHEMY_BINDS'] = {'lunch' : 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/lunch.db',
                                 'dinner' : 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/dinner.db',
                                 'snack' : 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/snack.db',
                                 'users' : 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/users.db',
                                 'list': 'sqlite:////Users/admin/Desktop/PROJECT_BOSCO/list.db'}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))

# БД страви
class Breakfast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    callor = db.Column(db.String(100), nullable=False)
    ingrid = db.Column(db.String(500), nullable=False)
    recept = db.Column(db.String(500), nullable=False)
    img = db.Column(db.Text, nullable=False)
    vgtr = db.Column(db.Text, nullable=False)
    nosgr = db.Column(db.Text, nullable=False)
    nolkt = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Breakfast %r>' % self.id


class Lunch(db.Model):
    __bind_key__ = 'lunch'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    callor = db.Column(db.String(100), nullable=False)
    ingrid = db.Column(db.String(500), nullable=False)
    recept = db.Column(db.String(500), nullable=False)
    img = db.Column(db.Text, nullable=False)
    vgtr = db.Column(db.Text, nullable=False)
    nosgr = db.Column(db.Text, nullable=False)
    nolkt = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Lunch %r>' % self.id

class Dinner(db.Model):
    __bind_key__ = 'dinner'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    callor = db.Column(db.String(100), nullable=False)
    ingrid = db.Column(db.String(500), nullable=False)
    recept = db.Column(db.String(500), nullable=False)
    img = db.Column(db.Text, nullable=False)
    vgtr = db.Column(db.Text, nullable=False)
    nosgr = db.Column(db.Text, nullable=False)
    nolkt = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Dinner %r>' % self.id

class Snack(db.Model):
    __bind_key__ = 'snack'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    callor = db.Column(db.String(100), nullable=False)
    img = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Snack %r>' % self.id

class List(db.Model):
    __bind_key__ = 'list'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    callor = db.Column(db.String(100), nullable=False)
    ingrid = db.Column(db.String(500))
    recept = db.Column(db.String(500))
    img = db.Column(db.Text, nullable=False)
    vgtr = db.Column(db.Text)
    nosgr = db.Column(db.Text)
    nolkt = db.Column(db.Text)

    def __repr__(self):
        return '<List %r>' % self.id

# БД користувачі
class Users(db.Model, UserMixin):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    names = db.Column(db.String(30))
    logins = db.Column(db.String(20), nullable=False, unique=True)
    passwords = db.Column(db.String(20), nullable=False)
    stat = db.Column(db.String(20))
    vaga = db.Column(db.String(20))
    rist = db.Column(db.String(20))
    calories = db.Column(db.String(20))

    def __repr__(self):
        return '<Users %r>' % self.id



class RegisterForm(FlaskForm):
    names = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Names"})
    logins = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Logins"})
    passwords = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Passwords"})
    submit = SubmitField("Register")

    def validate_username(self, logins):
        existing_user_username = Users.query.filter_by(
            username=logins.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a differend one."
            )

class LoginForm(FlaskForm):
    logins = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Logins"})
    passwords = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Passwords"})
    submit = SubmitField("Login")



# ----------------------------------------------------
# Вікна html


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/enter", methods=['POST', 'GET'])
def enter():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(logins=form.logins.data).first()
        if user:
            if bcrypt.check_password_hash(user.passwords, form.passwords.data):
                login_user(user)
                return redirect(url_for('users'))
    return render_template("enter.html", form=form)


     
# Функція додання користувачів

@app.route("/register", methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.passwords.data)
        new_user = Users(names=form.names.data, logins=form.logins.data, passwords=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('enter'))

    return render_template("register.html", form=form)


@app.route("/adminca", methods=['POST', 'GET'])
@login_required
def adminca():
    dis = Dinner.query.order_by(Dinner.title).all()
    lus = Lunch.query.order_by(Lunch.title).all()
    brs = Breakfast.query.order_by(Breakfast.title).all()
    sns = Snack.query.order_by(Snack.title).all()
    
    return render_template("adminca.html", di=dis, lu=lus, br=brs, sn=sns )


@app.route("/users", methods=['POST', 'GET'])
def users():
    dis = Dinner.query.order_by(Dinner.title).all()
    lus = Lunch.query.order_by(Lunch.title).all()
    brs = Breakfast.query.order_by(Breakfast.title).all()
    sns = Snack.query.order_by(Snack.title).all()
    return render_template("users.html", di=dis, lu=lus, br=brs, sn=sns)
    

@app.route("/users/<int:id>/adds")
def addb(id):
    item = Breakfast.query.get_or_404(id)

    lists = List(title=item.title, img=item.img, ingrid=item.ingrid, recept=item.recept, callor=item.callor, vgtr=item.vgtr, nosgr=item.nosgr, nolkt=item.nolkt)
    try:
        db.session.add(lists)
        db.session.commit()
        return redirect('/users')
    except:
        return "ERROR DB ADD"

@app.route("/users/<int:id>/addl")
def addl(id):
    item = Lunch.query.get_or_404(id)

    lists = List(title=item.title, img=item.img, ingrid=item.ingrid, recept=item.recept, callor=item.callor, vgtr=item.vgtr, nosgr=item.nosgr, nolkt=item.nolkt)
    try:
        db.session.add(lists)
        db.session.commit()
        return redirect('/users')
    except:
        return "ERROR DB ADD"

@app.route("/users/<int:id>/addd")
def addd(id):
    item = Dinner.query.get_or_404(id)

    lists = List(title=item.title, img=item.img, ingrid=item.ingrid, recept=item.recept, callor=item.callor, vgtr=item.vgtr, nosgr=item.nosgr, nolkt=item.nolkt)
    try:
        db.session.add(lists)
        db.session.commit()
        return redirect('/users')
    except:
        return "ERROR DB ADD"

@app.route("/users/<int:id>/addss")
def addss(id):
    item = Snack.query.get_or_404(id)

    lists = List(title=item.title, img=item.img, callor=item.callor)
    try:
        db.session.add(lists)
        db.session.commit()
        return redirect('/users')
    except:
        return "ERROR DB ADD"


@app.route("/list")
def lists():
    lis = List.query.order_by(List.title).all()

    return render_template("list.html", li=lis)


# DELETE LIST
@app.route("/list/<int:id>/deli")
def deleteli(id):
    item = List.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/list')
    except:
        return "ERROR DB DELETE"


# Видалення страв
@app.route("/adminca/<int:id>/del")
def deleteb(id):
    item = Breakfast.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/adminca')
    except:
        return "ERROR DB DELETE"

@app.route("/adminca/<int:id>/delete")
def deletel(id):
    item = Lunch.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/adminca')
    except:
        return "ERROR DB DELETE"

@app.route("/adminca/<int:id>/deleted")
def deleted(id):
    item = Dinner.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/adminca')
    except:
        return "ERROR DB DELETE"

@app.route("/adminca/<int:id>/deletes")
def deletes(id):
    item = Snack.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/adminca')
    except:
        return "ERROR DB DELETE"


# Функція вибору страв
@app.route("/choose", methods=['POST', 'GET'])
def choose():
    return render_template("choose.html")


# Функція додання страв
@app.route("/create", methods=['POST', 'GET'])
def create():
    if request.method == 'POST':
        title = request.form['title']
        img = request.form['img']
        ingrid = request.form['ingrid']
        recept = request.form['recept']
        callor = request.form['callor']
        vgtr = request.form['vgtr']
        nosgr = request.form['nosgr']
        nolkt = request.form['nolkt']

        item = Breakfast(title=title, img=img, ingrid=ingrid, recept=recept, callor=callor, vgtr=vgtr, nosgr=nosgr, nolkt=nolkt)

        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/adminca')
        except:
            return "ERROR DB"
    else:
        return render_template("create.html")

@app.route("/createl", methods=['POST', 'GET'])
def createl():
    if request.method == 'POST':
        title = request.form['title']
        img = request.form['img']
        ingrid = request.form['ingrid']
        recept = request.form['recept']
        callor = request.form['callor']
        vgtr = request.form['vgtr']
        nosgr = request.form['nosgr']
        nolkt = request.form['nolkt']

        item = Lunch(title=title, img=img, ingrid=ingrid, recept=recept, callor=callor, vgtr=vgtr, nosgr=nosgr, nolkt=nolkt)

        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/adminca')
        except:
            return "ERROR DB"
    else:
        return render_template("createl.html")

@app.route("/created", methods=['POST', 'GET'])
def created():
    if request.method == 'POST':
        title = request.form['title']
        img = request.form['img']
        ingrid = request.form['ingrid']
        recept = request.form['recept']
        callor = request.form['callor']
        vgtr = request.form['vgtr']
        nosgr = request.form['nosgr']
        nolkt = request.form['nolkt']

        item = Dinner(title=title, img=img, ingrid=ingrid, recept=recept, callor=callor, vgtr=vgtr, nosgr=nosgr, nolkt=nolkt)

        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/adminca')
        except:
            return "ERROR DB"
    else:
        return render_template("created.html")


@app.route("/creates", methods=['POST', 'GET'])
def creates():
    if request.method == 'POST':
        title = request.form['title']
        img = request.form['img']
        callor = request.form['callor']

        item = Snack(title=title, img=img, callor=callor)

        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/adminca')
        except:
            return "ERROR DB"
    else:
        return render_template("creates.html")



if __name__ == "__main__":
    app.run(debug=True)