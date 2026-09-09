# ============================================================
# REX AUTH SERVER - Single File (Render 호스팅용)
# ============================================================

import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'REX_SECRET_KEY_CHANGE_THIS')

DB_FILE = "database.db"


# ============================================================
# DB 초기화
# ============================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 관리자 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # 라이선스 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            expiry_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            note TEXT
        )
    ''')
    
    # 로그 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT,
            action TEXT,
            ip TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 기본 관리자 계정 (admin / admin123)
    admin_pw = hashlib.sha256("!!kkrtt1234".encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', admin_pw))
    except:
        pass
    
    conn.commit()
    conn.close()
    print("✅ 데이터베이스 초기화 완료")


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def log_action(hwid, action, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO logs (hwid, action, ip) VALUES (?, ?, ?)', (hwid, action, ip))
    conn.commit()
    conn.close()


# ============================================================
# 인증 API (RexClient가 호출)
# ============================================================

@app.route('/')
def index():
    return jsonify({
        'service': 'REX Auth Server',
        'status': 'online',
        'endpoints': {
            '/api/verify': 'POST - HWID 인증',
            '/admin': '관리자 페이지'
        }
    })


@app.route('/api/verify', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        hwid = data.get('hwid', '').upper()
        ip = request.remote_addr
        
        if not hwid:
            return jsonify({'success': False, 'message': 'HWID가 없습니다.'})
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM licenses WHERE hwid = ?', (hwid,))
        license_data = c.fetchone()
        conn.close()
        
        if not license_data:
            log_action(hwid, 'unregistered_attempt', ip)
            return jsonify({'success': False, 'message': '등록되지 않은 HWID입니다. 판매자에게 문의하세요.'})
        
        status = license_data['status']
        
        if status == 'pending':
            log_action(hwid, 'pending_attempt', ip)
            return jsonify({'success': False, 'message': '승인 대기 중입니다. 관리자가 승인하면 사용 가능합니다.'})
        
        elif status == 'revoked':
            log_action(hwid, 'revoked_attempt', ip)
            return jsonify({'success': False, 'message': '이 라이선스는 차단되었습니다.'})
        
        elif status == 'expired':
            log_action(hwid, 'expired_attempt', ip)
            return jsonify({'success': False, 'message': '라이선스가 만료되었습니다. 갱신이 필요합니다.'})
        
        elif status == 'approved':
            # 만료일 확인
            expiry = license_data['expiry_date']
            if expiry:
                expiry_date = datetime.strptime(expiry, '%Y-%m-%d')
                if datetime.now() > expiry_date:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute('UPDATE licenses SET status = "expired" WHERE hwid = ?', (hwid,))
                    conn.commit()
                    conn.close()
                    log_action(hwid, 'auto_expired', ip)
                    return jsonify({'success': False, 'message': '라이선스가 만료되었습니다.'})
            
            log_action(hwid, 'verified', ip)
            return jsonify({'success': True, 'message': '인증 성공! Rex Client를 사용할 수 있습니다.'})
        
        else:
            return jsonify({'success': False, 'message': '알 수 없는 상태입니다.'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'서버 오류: {str(e)}'})


# ============================================================
# 관리자 페이지 (HTML 직접 반환)
# ============================================================

HTML_LOGIN = '''
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🦖 REX Admin - Login</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0a0a0f;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}
.login-box {
    background: #1a1a2e;
    padding: 40px;
    border-radius: 16px;
    width: 380px;
    box-shadow: 0 0 40px rgba(255, 50, 50, 0.1);
}
.login-box h1 {
    color: #ff4444;
    font-size: 32px;
    text-align: center;
    margin-bottom: 8px;
}
.login-box .subtitle {
    color: #888;
    text-align: center;
    margin-bottom: 30px;
    font-size: 14px;
}
.login-box input {
    width: 100%;
    padding: 12px 16px;
    margin-bottom: 12px;
    background: #0a0a0f;
    border: 1px solid #333;
    border-radius: 8px;
    color: #fff;
    font-size: 14px;
}
.login-box input:focus {
    outline: none;
    border-color: #ff4444;
}
.login-box button {
    width: 100%;
    padding: 12px;
    background: #ff4444;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
    transition: background 0.3s;
}
.login-box button:hover {
    background: #ff6666;
}
.error {
    color: #f87171;
    text-align: center;
    margin-bottom: 12px;
    font-size: 14px;
}
.footer {
    text-align: center;
    margin-top: 20px;
    color: #555;
    font-size: 12px;
}
</style>
</head>
<body>
<div class="login-box">
    <h1>🦖 REX</h1>
    <div class="subtitle">Administrator Login</div>
    %s
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <div class="footer">REX Auth Server v1.0</div>
</div>
</body>
</html>
'''

HTML_ADMIN = '''
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🦖 REX Admin</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0a0a0f;
    color: #ccc;
    padding: 20px;
}
.container { max-width: 1200px; margin: 0 auto; }

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px;
    background: #1a1a2e;
    border-radius: 12px;
    margin-bottom: 30px;
}
.header h1 { color: #ff4444; font-size: 28px; }
.header .user { color: #888; }
.header .logout { color: #ff4444; text-decoration: none; }

.stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}
.stat-card {
    background: #1a1a2e;
    padding: 20px;
    border-radius: 12px;
    text-align: center;
}
.stat-card .number { font-size: 32px; font-weight: bold; }
.stat-card .label { color: #888; font-size: 14px; margin-top: 5px; }
.stat-card.green .number { color: #4ade80; }
.stat-card.yellow .number { color: #facc15; }
.stat-card.red .number { color: #f87171; }
.stat-card.blue .number { color: #60a5fa; }

.add-form {
    background: #1a1a2e;
    padding: 20px;
    border-radius: 12px;
    margin-bottom: 30px;
    display: flex;
    gap: 15px;
    align-items: center;
    flex-wrap: wrap;
}
.add-form input {
    background: #0a0a0f;
    border: 1px solid #333;
    color: #fff;
    padding: 10px 15px;
    border-radius: 8px;
    flex: 1;
    min-width: 200px;
}
.add-form input:focus {
    outline: none;
    border-color: #ff4444;
}
.add-form button {
    background: #ff4444;
    color: #fff;
    border: none;
    padding: 10px 30px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: bold;
}
.add-form button:hover { background: #ff6666; }

.table-wrap {
    background: #1a1a2e;
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 30px;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
    background: #0a0a0f;
    padding: 12px 15px;
    text-align: left;
    color: #888;
    font-size: 12px;
    text-transform: uppercase;
}
td {
    padding: 10px 15px;
    border-bottom: 1px solid #0a0a0f;
}
.status-badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
}
.status-badge.approved { background: #166534; color: #4ade80; }
.status-badge.pending { background: #713f12; color: #facc15; }
.status-badge.revoked { background: #7f1d1d; color: #f87171; }
.status-badge.expired { background: #1e293b; color: #94a3b8; }

.actions a {
    color: #60a5fa;
    text-decoration: none;
    margin-right: 10px;
    font-size: 13px;
}
.actions a:hover { text-decoration: underline; }
.actions a.danger { color: #f87171; }

.logs {
    background: #1a1a2e;
    border-radius: 12px;
    padding: 20px;
    max-height: 200px;
    overflow-y: auto;
}
.logs .log-entry {
    padding: 4px 0;
    border-bottom: 1px solid #0a0a0f;
    font-size: 12px;
    color: #888;
}
.logs .log-entry .time { color: #555; }
.logs .log-entry .hwid { color: #60a5fa; }

.hwid-code {
    font-family: 'Courier New', monospace;
    font-size: 12px;
    color: #60a5fa;
}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>🦖 REX Admin</h1>
        <div>
            <span class="user">%s</span>
            <a href="/logout" class="logout">로그아웃</a>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card blue">
            <div class="number">%d</div>
            <div class="label">전체</div>
        </div>
        <div class="stat-card green">
            <div class="number">%d</div>
            <div class="label">승인됨</div>
        </div>
        <div class="stat-card yellow">
            <div class="number">%d</div>
            <div class="label">대기중</div>
        </div>
        <div class="stat-card red">
            <div class="number">%d</div>
            <div class="label">차단됨</div>
        </div>
    </div>

    <form class="add-form" method="POST" action="/admin/add">
        <input type="text" name="hwid" placeholder="HWID 입력 (예: A3F8D9E1...)" required>
        <input type="number" name="days" value="365" style="flex:0.3; min-width:80px;">
        <input type="text" name="note" placeholder="비고 (선택)" style="flex:0.5; min-width:150px;">
        <button type="submit">➕ 등록</button>
    </form>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>HWID</th>
                    <th>상태</th>
                    <th>만료일</th>
                    <th>등록일</th>
                    <th>비고</th>
                    <th>관리</th>
                </tr>
            </thead>
            <tbody>
                %s
            </tbody>
        </table>
    </div>

    <div class="logs">
        <h3 style="color:#888; margin-bottom:10px;">📋 최근 로그</h3>
        %s
    </div>

</div>
</body>
</html>
'''


# ============================================================
# 라우트
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = hashlib.sha256(request.form.get('password', '').encode()).hexdigest()
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect('/admin')
        
        return HTML_LOGIN % '<div class="error">❌ 아이디 또는 비밀번호가 틀렸습니다.</div>'
    
    return HTML_LOGIN % ''


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    c = conn.cursor()
    
    total = c.execute('SELECT COUNT(*) FROM licenses').fetchone()[0]
    approved = c.execute('SELECT COUNT(*) FROM licenses WHERE status="approved"').fetchone()[0]
    pending = c.execute('SELECT COUNT(*) FROM licenses WHERE status="pending"').fetchone()[0]
    revoked = c.execute('SELECT COUNT(*) FROM licenses WHERE status="revoked"').fetchone()[0]
    
    c.execute('SELECT * FROM licenses ORDER BY id DESC LIMIT 100')
    licenses = c.fetchall()
    
    # 로그 가져오기
    c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 20')
    logs = c.fetchall()
    
    conn.close()
    
    # 테이블 행 생성
    table_rows = ''
    for r in licenses:
        status = r['status']
        badge = f'<span class="status-badge {status}">{status}</span>'
        
        actions = ''
        if status == 'pending':
            actions += f'<a href="/admin/approve/{r["hwid"]}">✅ 승인</a>'
        if status == 'approved':
            actions += f'<a href="/admin/revoke/{r["hwid"]}" class="danger">⛔ 차단</a>'
        if status == 'revoked':
            actions += f'<a href="/admin/approve/{r["hwid"]}">↩️ 복구</a>'
        actions += f'<a href="/admin/delete/{r["hwid"]}" class="danger" onclick="return confirm(\'삭제하시겠습니까?\')">🗑 삭제</a>'
        
        table_rows += f'''
        <tr>
            <td><span class="hwid-code">{r["hwid"][:24]}...</span></td>
            <td>{badge}</td>
            <td>{r["expiry_date"] or "-"}</td>
            <td>{r["created_at"][:10] if r["created_at"] else "-"}</td>
            <td>{r["note"] or "-"}</td>
            <td class="actions">{actions}</td>
        </tr>
        '''
    
    # 로그 HTML
    log_html = ''
    for log in logs:
        log_html += f'''
        <div class="log-entry">
            <span class="time">[{log["timestamp"]}]</span>
            <span class="hwid">{log["hwid"][:16]}...</span>
            {log["action"]}
            <span style="color:#555;">({log["ip"]})</span>
        </div>
        '''
    
    return HTML_ADMIN % (session.get('username'), total, approved, pending, revoked, table_rows, log_html)


@app.route('/admin/add', methods=['POST'])
def add_license():
    if not session.get('logged_in'):
        return redirect('/login')
    
    hwid = request.form.get('hwid', '').upper().strip()
    note = request.form.get('note', '')
    days = int(request.form.get('days', 365))
    
    if not hwid:
        return 'HWID가 없습니다.', 400
    
    expiry = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO licenses (hwid, status, expiry_date, note)
            VALUES (?, 'pending', ?, ?)
        ''', (hwid, expiry, note))
        conn.commit()
        conn.close()
        return redirect('/admin')
    except sqlite3.IntegrityError:
        conn.close()
        return '이미 등록된 HWID입니다.', 400


@app.route('/admin/approve/<hwid>')
def approve_license(hwid):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE licenses SET status = "approved" WHERE hwid = ?', (hwid,))
    conn.commit()
    conn.close()
    return redirect('/admin')


@app.route('/admin/revoke/<hwid>')
def revoke_license(hwid):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE licenses SET status = "revoked" WHERE hwid = ?', (hwid,))
    conn.commit()
    conn.close()
    return redirect('/admin')


@app.route('/admin/delete/<hwid>')
def delete_license(hwid):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM licenses WHERE hwid = ?', (hwid,))
    conn.commit()
    conn.close()
    return redirect('/admin')


# ============================================================
# 실행
# ============================================================

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("🦖 REX AUTH SERVER")
    print("=" * 50)
    print("관리자 계정: admin / admin123")
    print("관리자 페이지: http://localhost:5000/admin")
    print("=" * 50)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
