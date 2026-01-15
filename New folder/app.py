#==================== AUTH ROUTES ====================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dasboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
if

