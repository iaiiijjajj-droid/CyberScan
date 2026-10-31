import os, time, sqlite3, base64, re
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
VT_BASE = 'https://www.virustotal.com/api/v3'
DB_PATH = os.getenv('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'scans.db'))


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            malicious INTEGER NOT NULL,
            suspicious INTEGER NOT NULL,
            harmless INTEGER NOT NULL,
            undetected INTEGER NOT NULL,
            source TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )''')


def normalize_url(raw):
    value = (raw or '').strip()
    if not value:
        raise ValueError('أدخل رابطاً أولاً.')
    if len(value) > 2048:
        raise ValueError('الرابط طويل جداً.')
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value):
        value = 'https://' + value
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('الرابط غير صحيح. استخدم رابطاً يبدأ بـ http:// أو https://')
    if any(ch.isspace() for ch in value):
        raise ValueError('الرابط يحتوي على مسافات غير مسموحة.')
    return value


def vt_request(method, path, **kwargs):
    if not VT_API_KEY:
        raise RuntimeError('مفتاح VirusTotal غير مضبوط. أضف VIRUSTOTAL_API_KEY إلى ملف .env.')
    headers = {'x-apikey': VT_API_KEY, 'accept': 'application/json'}
    if 'headers' in kwargs:
        headers.update(kwargs.pop('headers'))
    try:
        response = requests.request(method, VT_BASE + path, headers=headers, timeout=25, **kwargs)
    except requests.RequestException:
        raise RuntimeError('تعذر الاتصال بخدمة VirusTotal. تحقق من الإنترنت وحاول مرة أخرى.')
    if response.status_code == 401:
        raise RuntimeError('مفتاح API غير صحيح أو غير صالح. تحقق من المفتاح في VirusTotal.')
    if response.status_code == 429:
        raise RuntimeError('تم تجاوز حد الطلبات المسموح به حالياً. انتظر قليلاً ثم أعد المحاولة.')
    if response.status_code == 403:
        raise RuntimeError('المفتاح لا يملك صلاحية هذا الطلب، أو توجد قيود على الحساب.')
    if response.status_code >= 400:
        if response.status_code == 404:
            return response
        raise RuntimeError(f'VirusTotal أعاد خطأ (HTTP {response.status_code}).')
    return response


def url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def get_report(url):
    # First try existing report. If not known, submit URL for analysis.
    response = vt_request('GET', '/urls/' + url_id(url))
    if response.status_code == 404:
        submitted = vt_request('POST', '/urls', data={'url': url})
        analysis_id = submitted.json().get('data', {}).get('id')
        if not analysis_id:
            raise RuntimeError('تم إرسال الرابط لكن لم نستلم معرّف التحليل من VirusTotal.')
        data = None
        # Poll briefly; VirusTotal may need more time, so don't invent a result.
        for _ in range(8):
            time.sleep(2)
            analysis = vt_request('GET', '/analyses/' + analysis_id).json().get('data', {}).get('attributes', {})
            if analysis.get('status') == 'completed':
                stats = analysis.get('stats') or {}
                data = {'attributes': {'last_analysis_stats': stats, 'last_analysis_date': int(time.time())}}
                break
        if data is None:
            return {'pending': True}
    else:
        data = response.json().get('data', {}).get('attributes', {})
    if 'attributes' in data:
        attrs = data['attributes']
    else:
        attrs = data
    stats = attrs.get('last_analysis_stats') or {}
    # Analysis response stats may be under stats, normalize fields.
    malicious = int(stats.get('malicious', 0) or 0)
    suspicious = int(stats.get('suspicious', 0) or 0)
    harmless = int(stats.get('harmless', 0) or 0)
    undetected = int(stats.get('undetected', 0) or 0)
    total = malicious + suspicious + harmless + undetected
    score = round(100 * (malicious + 0.5 * suspicious) / total) if total else 0
    if malicious > 0:
        verdict = 'خبيث'
    elif suspicious > 0:
        verdict = 'مشبوه'
    elif total > 0:
        verdict = 'لم تُكتشف تهديدات'
    else:
        verdict = 'نتيجة غير مكتملة'
    return {'pending': False, 'malicious': malicious, 'suspicious': suspicious,
            'harmless': harmless, 'undetected': undetected, 'score': score,
            'verdict': verdict, 'total': total}


@app.route('/')
def home():
    return render_template('index.html')


@app.post('/api/scan')
def scan():
    body = request.get_json(silent=True) or {}
    try:
        url = normalize_url(body.get('url', ''))
        result = get_report(url)
        if result.get('pending'):
            return jsonify({'ok': True, 'pending': True, 'url': url,
                            'message': 'أُرسل الرابط إلى VirusTotal، لكن التحليل لم يكتمل بعد. انتظر قليلاً ثم أعد الفحص.'})
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with db() as conn:
            conn.execute('''INSERT INTO scans(url, verdict, score, malicious, suspicious, harmless, undetected, source, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (url, result['verdict'], result['score'], result['malicious'], result['suspicious'],
                 result['harmless'], result['undetected'], 'VirusTotal', now))
        result.update({'ok': True, 'url': url, 'scanned_at': now, 'source': 'VirusTotal'})
        return jsonify(result)
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    except RuntimeError as e:
        return jsonify({'ok': False, 'error': str(e)}), 502


@app.get('/api/history')
def history():
    with db() as conn:
        rows = conn.execute('SELECT id,url,verdict,score,malicious,suspicious,harmless,undetected,source,scanned_at FROM scans ORDER BY id DESC LIMIT 20').fetchall()
    return jsonify([dict(row) for row in rows])


@app.get('/health')
def health():
    return jsonify({'status': 'ok'})


init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
