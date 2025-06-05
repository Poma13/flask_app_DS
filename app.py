import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, UserMixin, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm, CreateServerForm
import uuid
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room


app = Flask(__name__)
app.config['SECRET_KEY'] = 'roman_molodec'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:postgres@localhost/vhod_db"


socketio = SocketIO(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    nickname = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender',
                                    lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver',
                                        lazy='dynamic')


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_messages')


class Server(db.Model):
    __tablename__ = 'server'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    creator = db.relationship('User', foreign_keys=[creator_id])
    messages = db.relationship('ServerMessage', back_populates='server', lazy='dynamic')


class ServerMember(db.Model):
    __tablename__ = 'server_member'

    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    # status = db.Column(db.String(20), nullable=True, default='n')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class ServerMessage(db.Model):
    __tablename__ = 'server_message'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    sender = db.relationship('User', foreign_keys=[sender_id])
    server = db.relationship('Server', foreign_keys=[server_id])


class CallMember(db.Model):
    __tablename__ = 'call_member'

    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    joined_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    server = db.relationship('Server', backref='call_members')
    user = db.relationship('User')



with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Вы успешно зашли в систему!", "success")
            return redirect(url_for('users'))
    return render_template("login.html", form=form)


#@app.route('/users')
@app.route("/")
@login_required
def users():
    # Получаем только друзей
    friend_ids = [f.friend_id for f in Friendship.query.filter_by(user_id=current_user.id).all()]
    friends = User.query.filter(User.id.in_(friend_ids)).all()

    # Получаем серверы пользователя
    server_ids = [sm.server_id for sm in ServerMember.query.filter_by(user_id=current_user.id).all()]
    servers = Server.query.filter(Server.id.in_(server_ids)).all()

    return render_template('users.html', friends=friends, servers=servers)


@app.route('/add_friend/<int:friend_id>', methods=["POST"])
@login_required
def add_friend(friend_id):
    if friend_id == current_user.id:
        return redirect(url_for('users'))

    existing = Friendship.query.filter_by(user_id=current_user.id, friend_id=friend_id).first()
    if not existing:
        friendship1 = Friendship(user_id=current_user.id, friend_id=friend_id)
        friendship2 = Friendship(user_id=friend_id, friend_id=current_user.id)
        db.session.add(friendship1)
        db.session.add(friendship2)
        db.session.commit()
    return redirect(url_for('users'))


@app.route('/remove_friend/<int:friend_id>', methods=["GET", "POST"])
@login_required
def remove_friend(friend_id):
    if friend_id == current_user.id:
        return redirect(url_for('users'))

    existing = Friendship.query.filter_by(user_id=current_user.id, friend_id=friend_id).first()
    if existing:
        Friendship.query.filter_by(user_id=current_user.id, friend_id=friend_id).delete()
        Friendship.query.filter_by(user_id=friend_id, friend_id=current_user.id).delete()
        db.session.commit()

    return redirect(url_for('users'))



@app.route('/chat/<int:friend_id>', methods=["GET", "POST"])
@login_required
def chat(friend_id):
    friend = User.query.get_or_404(friend_id)

    if request.method == "POST":
        message = request.form.get("message")
        if message:
            new_msg = Message(sender_id=current_user.id, receiver_id=friend_id, content=message)
            db.session.add(new_msg)
            db.session.commit()
        return redirect(url_for('chat', friend_id=friend_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == friend_id)) |
        ((Message.sender_id == friend_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    for msg in messages:
        if msg.timestamp:
            msg.timestamp = msg.timestamp + timedelta(hours=4)

    return render_template("chat.html", friend=friend, messages=messages)


@app.route('/create_server', methods=['GET', 'POST'])
@login_required
def create_server():
    form = CreateServerForm()

    # Получаем список друзей
    friends = User.query.join(Friendship, User.id == Friendship.friend_id) \
        .filter(Friendship.user_id == current_user.id).all()

    if request.method == 'POST':
        # Вручную обрабатываем данные формы
        server_name = request.form.get('name')
        selected_members = request.form.getlist('members')

        # Валидация
        if not server_name or not server_name.isalnum():
            flash('Название сервера должно содержать только буквы и цифры', 'error')
        elif len(selected_members) < 1:
            flash('Нужно добавить хотя бы одного участника', 'error')
        else:
            # Создаем сервер
            new_server = Server(
                name=server_name,
                creator_id=current_user.id
            )
            db.session.add(new_server)
            db.session.flush()

            # Добавляем участников
            db.session.add(ServerMember(server_id=new_server.id, user_id=current_user.id))
            for member_id in selected_members:
                db.session.add(ServerMember(server_id=new_server.id, user_id=member_id))

            db.session.commit()
            flash('Сервер успешно создан!', 'success')
            return redirect(url_for('server_chat', server_id=new_server.id))

    return render_template('create_server.html', form=form, friends=friends)


@app.route('/server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def server_chat(server_id):
    # Проверяем, что пользователь участник сервера
    is_member = ServerMember.query.filter_by(
        server_id=server_id,
        user_id=current_user.id
    ).first()

    if not is_member:
        flash('У вас нет доступа к этому серверу', 'error')
        return redirect(url_for('users'))

    server = Server.query.get_or_404(server_id)

    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            new_msg = ServerMessage(
                sender_id=current_user.id,
                server_id=server_id,
                content=message
            )
            db.session.add(new_msg)
            db.session.commit()
        return redirect(url_for('server_chat', server_id=server_id))

    # Получаем сообщения
    messages = ServerMessage.query.filter_by(server_id=server_id) \
        .order_by(ServerMessage.timestamp.asc()).all()

    # Получаем участников сервера
    members = User.query.join(ServerMember, User.id == ServerMember.user_id) \
        .filter(ServerMember.server_id == server_id).all()

    # Корректировка времени
    for msg in messages:
        if msg.timestamp:
            msg.timestamp = msg.timestamp + timedelta(hours=4)

    return render_template('server_chat.html',
                           server=server,
                           messages=messages,
                           members=members)



'''@app.route('/servers')
@login_required
def user_servers():
    # Получаем серверы пользователя
    servers = Server.query.join(ServerMember, Server.id == ServerMember.server_id) \
        .filter(ServerMember.user_id == current_user.id).all()

    return render_template('users.html', servers=servers)'''


@app.route("/chat")
@login_required
def chat_index():
    friend = User.query.first()
    return render_template('chat.html', friend=friend)


@app.route('/finduser', methods=['GET', 'POST'])
@login_required
def find_user():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        return render_template('finduser.html', user=user, searched_username=username)
    return render_template('finduser.html')


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if 'nickname' in request.form:
        current_user.nickname = request.form['nickname'] or None

    if 'avatar' in request.files:
        avatar = request.files['avatar']
        if avatar.filename != '':
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join('static/avatars', filename))
            current_user.avatar = filename

    db.session.commit()
    return redirect(request.referrer or url_for('users'))


@app.route('/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)

    # Проверяем что текущий пользователь - создатель сервера
    if server.creator_id != current_user.id:
        flash('Только создатель может распустить сервер', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    # Удаляем все записи об участниках сервера
    ServerMember.query.filter_by(server_id=server_id).delete()
    Server.query.filter_by(id=server_id).delete()

    # Удаляем сам сервер
    #db.session.delete(server)
    db.session.commit()

    flash('Сервер успешно распущен', 'success')
    return redirect(url_for('users'))


@app.route('/remove_member/<int:server_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member(server_id, user_id):
    server = Server.query.get_or_404(server_id)
    user = User.query.get_or_404(user_id)

    # Проверяем, что текущий пользователь — админ или создатель сервера
    if current_user.id != server.creator_id:
        flash('Только создатель сервера может исключать участников', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    # Проверяем, что пользователь не пытается удалить себя или создателя
    if user_id == server.creator_id:
        flash('Нельзя исключить создателя сервера', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    # Удаляем запись из ServerMember
    membership = ServerMember.query.filter_by(
        server_id=server_id,
        user_id=user_id
    ).first()

    if membership:
        db.session.delete(membership)
        msg = ServerMessage(
            sender_id=current_user.id,
            server_id=server_id,
            content=f'Пользователь {user.nickname} исключен'
        )
        db.session.add(msg)
        db.session.commit()
        flash('Пользователь успешно исключен', 'success')
    else:
        flash('Пользователь не найден на сервере', 'error')

    # Перенаправляем обратно в чат сервера
    return redirect(url_for('server_chat', server_id=server_id))



@app.route('/leave_server/<int:server_id>/<int:user_id>', methods=['GET', 'POST'])
def leave_server(server_id, user_id):
    server = Server.query.get_or_404(server_id)
    user = User.query.get_or_404(user_id)

    # Проверяем, что пользователь не пытается удалить себя или создателя
    if user_id != current_user.id:
        flash('Так нельзя!', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    # Удаляем запись из ServerMember
    membership = ServerMember.query.filter_by(
        server_id=server_id,
        user_id=user_id
    ).first()

    if membership:
        db.session.delete(membership)
        msg = ServerMessage(
            sender_id=server.creator_id,
            server_id=server.id,
            content=f'Пользователь {user.nickname} покинул сервер'
        )
        db.session.add(msg)
        db.session.commit()

    else:
        flash('Пользователь не найден на сервере', 'error')

    # Перенаправляем обратно в чат сервера
    return redirect(url_for('server_chat', server_id=server_id))


@app.route('/add_members/<int:server_id>', methods=['GET'])
@login_required
def add_members_page(server_id):
    server = Server.query.get_or_404(server_id)

    # Проверяем права (только создатель сервера может добавлять участников)
    if server.creator_id != current_user.id:
        flash('Только создатель сервера может добавлять участников', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    # Получаем друзей, которые еще не на сервере
    current_members = [m.user_id for m in ServerMember.query.filter_by(server_id=server_id).all()]
    friends = User.query.join(Friendship, User.id == Friendship.friend_id) \
        .filter(Friendship.user_id == current_user.id) \
        .filter(User.id.notin_(current_members)) \
        .all()

    return render_template('add_members.html', server=server, friends=friends)


@app.route('/add_members/<int:server_id>', methods=['POST'])
@login_required
def add_members(server_id):
    server = Server.query.get_or_404(server_id)

    if server.creator_id != current_user.id:
        flash('Только создатель сервера может добавлять участников', 'error')
        return redirect(url_for('server_chat', server_id=server_id))

    selected_members = request.form.getlist('members')

    if not selected_members:
        flash('Выберите хотя бы одного участника', 'error')
        return redirect(url_for('add_members_page', server_id=server_id))

    # Добавляем выбранных участников
    for member_id in selected_members:
        if not ServerMember.query.filter_by(server_id=server_id, user_id=member_id).first():
            db.session.add(ServerMember(server_id=server_id, user_id=member_id))
            user = User.query.get_or_404(member_id)
            msg = ServerMessage(
                sender_id=server.creator_id,
                server_id=server.id,
                content=f'Пользователь {user.nickname} добавлен на сервер'
            )
            db.session.add(msg)



    db.session.commit()
    flash('Участники успешно добавлены', 'success')
    return redirect(url_for('server_chat', server_id=server_id))


# CALL
@app.route('/servers/<int:server_id>/start_call', methods=['POST'])
@login_required
def start_call(server_id):
    server = Server.query.get_or_404(server_id)

    # Удаляем всех участников из возможных старых звонков
    CallMember.query.filter_by(user_id=current_user.id).delete()

    # Добавляем текущего пользователя как участника звонка
    call_member = CallMember(server_id=server.id, user_id=current_user.id)
    db.session.add(call_member)
    db.session.commit()

    return redirect(url_for('join_call', server_id=server.id))


@app.route('/servers/<int:server_id>/join_call')
@login_required
def join_call(server_id):
    server = Server.query.get_or_404(server_id)

    # Проверка: если пользователь уже в другом звонке — не пускаем
    other_call = CallMember.query.filter(CallMember.user_id == current_user.id,
                                         CallMember.server_id != server_id).first()
    if other_call:
        flash('Вы уже участвуете в другом звонке!')
        return redirect(url_for('server_chat', server_id=server_id))

    # Если не в звонке, добавим
    existing = CallMember.query.filter_by(server_id=server_id, user_id=current_user.id).first()
    if not existing:
        db.session.add(CallMember(server_id=server_id, user_id=current_user.id))
        db.session.commit()

    return redirect(url_for('server_call', server_id=server_id))


@app.route('/servers/<int:server_id>/leave_call', methods=['POST'])
@login_required
def leave_call(server_id):
    # Удаляем участника звонка
    CallMember.query.filter_by(server_id=server_id, user_id=current_user.id).delete()
    db.session.commit()

    flash("Вы покинули звонок", "info")
    return redirect(url_for('server_chat', server_id=server_id))



@app.route('/servers/<int:server_id>/call')
@login_required
def server_call(server_id):
    server = Server.query.get_or_404(server_id)
    call_members = CallMember.query.filter_by(server_id=server_id).all()
    members_info = [{
        'id': member.user.id,
        'nickname': member.user.nickname,
        'username': member.user.username,
        'avatar': member.user.avatar
    } for member in call_members]

    return render_template('server_call.html', server=server, members=members_info, current_user_id=current_user.id)



@socketio.on('join_call')
def handle_join(data):
    room = str(data['room'])
    join_room(room)
    emit('user-joined', {'id': request.sid}, room=room, include_self=False)

@socketio.on('signal')
def handle_signal(data):
    to = data['to']
    signal = data['signal']
    emit('signal', {'from': request.sid, 'signal': signal}, room=to)

@socketio.on('disconnect')
def handle_disconnect():
    emit('user-left', {'id': request.sid}, broadcast=True)


# ENDCALL



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы", "info")
    return redirect(url_for('login'))


if __name__ == "__main__":
    socketio.run(app, debug=True, port=8000)
