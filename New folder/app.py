#==================== AUTH ROUTES ====================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dasboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
if request.method == 'POST':
    data = request.get_json()
    username = data.get('username','').strip()
    email = data.get('email', '').strip()
    password = data.get('password','')
    confirm_password = data.get('confirm_password','')
    master_key = data.get('master_key','')

    # Validation
    if not all([username, email, password, confirm_password, master_key]):
        return jsonify({'success' : False, 'message': 'All field required'}), 400
    
    if len(username) < 3:
        return jsonify({'success' : False, 'message' : 'Username must be at least 3 characters'}), 400

    if password != confirm_password:
        return jsonify({'success' : False, 'message' : 'Paswords do not match'}), 400 
    
    if len(master_key) < 4:
        return jsonify({'success' : False, 'message' : 'Master key must be at least 4 characters'}), 400
    
    # Check if user exists
    if User.query.filter_by(username=username).first():
        return jsonify({'success' : False, 'message' : 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success' : False, 'message' : 'Email already registered'}), 400
    
    # Create verification code
    verification_code = generate_verification_code()

    # Create user
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        master_key_hash=generate_password_hash(password),
        verification_code=verification_code,
        verification_code_expires=datetime.utcnow() + timedelta(hours=1)
    ) 

    db.session.add(user)
    db.session.commit()

    