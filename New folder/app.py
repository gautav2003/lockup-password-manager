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
    
    