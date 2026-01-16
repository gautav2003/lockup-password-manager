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

    #Send verification email
    email_body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
             <div style="max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow:v0 2px 10px rgba(0,0,0,0.1);">
                 <h2 style="color: #333; text-align: center; ">Welcome to Lockup</h2>
                 <p style="color: #666; font-size: 16px; ">Your verification code is:</p>
                 <p style="background-color: #f0f0f0; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #FF4444; border-radius: 5px; letter-spacing: 5px;">
                     {verification_code}
                </p>
                <p style="color: #999; font-size: 14px; text-align: center;">This code expries in 1 hour.</p> 
            </div>
        </body>
    </html>
    """

    send_email(email, 'Lockup - Verify Your Email', email_body, is_html=True)

    return jsonify({
        'success' : True,
        'message' : 'Signup successful! Check your email for verification code. ',
        'email': email,
        'user_id': user.id
    }), 201

return render_template('signup.html')

@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    user_id = data.get('user_id')
    code = data.get('code')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.verification_code != code:
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
    
    if user.verufication_code_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Verification code expired'}), 400
    
    user.is_verified = True
    user.verification_code = None
    db.session.commit()

    return jsonify({'succss': True, 'message': 'Email verified successfully'}), 200

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip()

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'Email not found'}), 404
        