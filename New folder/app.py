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

    

