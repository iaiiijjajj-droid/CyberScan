"""محركات التحليل المحلي: روابط، محتوى QR، وتحليل ثابت للأكواد.

كل التحليل هنا يعتمد على قواعد وأنماط (Heuristics) ولا يرسل أي بيانات لجهة خارجية.
النتائج مؤشرات تساعد على المراجعة وليست حكماً نهائياً.
"""
import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

SEV_WEIGHT_URL = {'high': 40, 'medium': 20, 'low': 8, 'info': 0}
SEV_WEIGHT_CODE = {'high': 20, 'medium': 8, 'low': 3, 'info': 0}
SEV_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}

# ---------------------------------------------------------------------------
# تحليل الروابط محلياً
# ---------------------------------------------------------------------------
DANGEROUS_SCHEMES = {
    'javascript': 'ينفّذ كود جافاسكربت داخل المتصفح عند فتحه.',
    'data': 'يضمّن محتوى كاملاً (قد يكون صفحة تصيّد) داخل الرابط نفسه.',
    'vbscript': 'ينفّذ سكربت VBScript وهو نمط قديم يُستخدم في الهجمات.',
    'file': 'يشير إلى ملف محلي على جهازك وليس إلى موقع.',
}
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly', 's.id', 'lnkd.in', 'qrco.de',
    'v.gd', 'bit.do', 'shorte.st', 'adf.ly', 'bl.ink', 'soo.gd', 'clck.ru', 'tr.ee',
}
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'work', 'loan', 'country', 'kim',
    'men', 'zip', 'mov', 'icu', 'monster', 'cyou', 'buzz', 'rest', 'support', 'link',
}
TWO_PART_SUFFIXES = {
    'co.uk', 'org.uk', 'com.au', 'com.iq', 'gov.iq', 'edu.iq', 'org.iq', 'net.iq',
    'com.tr', 'com.sa', 'com.eg', 'co.in', 'com.br', 'co.jp',
}
BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram', 'whatsapp',
    'telegram', 'netflix', 'binance', 'dhl', 'zain', 'asiacell', 'korek', 'tiktok', 'snapchat',
]
OFFICIAL_DOMAINS = {
    'google.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'goo.gl', 'google.iq',
    'microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'apple.com', 'icloud.com',
    'amazon.com', 'amazonaws.com', 'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com',
    'wa.me', 'whatsapp.net', 'telegram.org', 't.me', 'netflix.com', 'paypal.com', 'paypal.me',
    'binance.com', 'dhl.com', 'zain.com', 'asiacell.com', 'korektel.com', 'tiktok.com',
    'snapchat.com',
}
PHISH_WORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update', 'confirm',
    'password', 'wallet', 'bank', 'gift', 'prize', 'claim', 'free', 'bonus', 'recover',
    'suspend', 'unlock', 'billing', 'invoice',
]
RISKY_EXTENSIONS = (
    '.apk', '.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.ps1', '.vbs', '.hta', '.lnk',
    '.iso', '.dmg', '.docm', '.xlsm',
)
BARE_DOMAIN_RE = re.compile(r'^(?:[a-z0-9\u0080-\uffff-]+\.)+[a-z\u0080-\uffff]{2,}(?::\d+)?(?:[/?#]\S*)?$', re.I)


def _finding(sev, title, desc):
    return {'severity': sev, 'title': title, 'desc': desc}


def risk_from_findings(findings, weights=SEV_WEIGHT_URL, cap=100):
    score = min(cap, sum(weights.get(f['severity'], 0) for f in findings))
    if score >= 40:
        level = 'high'
    elif score >= 20:
        level = 'medium'
    elif score > 0:
        level = 'low'
    else:
        level = 'none'
    return score, level


def registered_domain(host):
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    if '.'.join(parts[-2:]) in TWO_PART_SUFFIXES:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def analyze_url_local(raw):
    """يرجع تحليلاً محلياً للرابط دون أي اتصال بالإنترنت."""
    value = (raw or '').strip()
    findings = []
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', value)
    scheme_only = m.group(1).lower() if m else ''
    if scheme_only in DANGEROUS_SCHEMES and not value.lower().startswith(scheme_only + '://'):
        findings.append(_finding('high', f'مخطط خطير: {scheme_only}:', DANGEROUS_SCHEMES[scheme_only]))
        score, level = risk_from_findings(findings)
        return {'normalized': value[:300], 'host': '', 'findings': findings, 'score': score, 'risk': level}

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value):
        value = 'https://' + value
    try:
        p = urlparse(value)
        host = (p.hostname or '').lower()
        port = p.port
    except ValueError:
        findings.append(_finding('medium', 'رابط بصيغة غير صالحة', 'لم نتمكن من تفكيك الرابط بشكل سليم، وقد يكون متعمداً للتحايل.'))
        score, level = risk_from_findings(findings)
        return {'normalized': value[:300], 'host': '', 'findings': findings, 'score': score, 'risk': level}

    if p.scheme == 'http':
        findings.append(_finding('low', 'اتصال غير مشفّر (HTTP)', 'البيانات التي تدخلها قد تُقرأ أثناء النقل. المواقع الموثوقة تستخدم HTTPS.'))
    elif p.scheme not in ('https',):
        findings.append(_finding('medium', f'بروتوكول غير معتاد: {p.scheme}', 'الروابط العادية تبدأ بـ http أو https.'))

    if '@' in p.netloc:
        findings.append(_finding('high', 'الرابط يحتوي على @', 'ما قبل علامة @ يُتجاهل كاسم مستخدم، والموقع الحقيقي هو ما بعدها. أسلوب شائع للتمويه.'))

    is_ip = False
    if host:
        try:
            ip = ipaddress.ip_address(host)
            is_ip = True
            if ip.is_private or ip.is_loopback:
                findings.append(_finding('info', 'عنوان محلي', 'الرابط يشير إلى جهاز أو شبكة داخلية وليس إلى موقع عام.'))
            else:
                findings.append(_finding('medium', 'الرابط يستخدم عنوان IP بدل اسم موقع', 'المواقع الشرعية نادراً ما تُوزَّع عبر عنوان IP مباشر، وهو أسلوب متكرر في التصيّد.'))
        except ValueError:
            if re.fullmatch(r'\d{8,10}', host) or re.fullmatch(r'0x[0-9a-f]+', host):
                is_ip = True
                findings.append(_finding('high', 'عنوان IP مُخفى بصيغة رقمية', 'الرقم الطويل أو الست عشري قد يكون عنوان IP متنكراً لإخفاء الوجهة الحقيقية.'))

    if host and not is_ip:
        labels = host.split('.')
        if any(ord(c) > 127 for c in host):
            findings.append(_finding('medium', 'اسم الموقع يحتوي حروفاً غير لاتينية', 'قد يُستخدم حرف يشبه حرفاً إنجليزياً لانتحال موقع معروف (هجوم تشابه الحروف).'))
        if any(l.startswith('xn--') for l in labels):
            findings.append(_finding('medium', 'اسم موقع بصيغة Punycode', 'بداية xn-- تعني اسماً دولياً مُرمّزاً؛ تحقق أنه لا ينتحل موقعاً معروفاً.'))
        reg = registered_domain(host)
        if reg in SHORTENERS or host in SHORTENERS:
            findings.append(_finding('medium', 'رابط مختصر', 'الوجهة الحقيقية مخفية. افحص الرابط أولاً ولا تفتحه مباشرة.'))
        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(_finding('low', f'امتداد نطاق شائع في الإساءة (.{tld})', 'هذا الامتداد رخيص أو مجاني وكثيراً ما يُستغل في حملات الاحتيال، لكنه ليس دليلاً بحد ذاته.'))
        sub_count = len(labels) - len(reg.split('.'))
        if sub_count >= 3:
            findings.append(_finding('low', 'نطاقات فرعية كثيرة', 'تكرار النطاقات الفرعية قد يُخفي الاسم الحقيقي للموقع في نهاية العنوان.'))
        if host.count('-') >= 3:
            findings.append(_finding('low', 'اسم الموقع يحتوي شرطات كثيرة', 'الأسماء الطويلة المركبة شائعة في مواقع التصيّد.'))
        if reg not in OFFICIAL_DOMAINS:
            for brand in BRANDS:
                if brand in host:
                    findings.append(_finding('medium', f'يذكر اسم «{brand}» لكن النطاق ليس الرسمي المعروف له',
                                             f'النطاق الأساسي هنا «{reg}». تأكد أنك تقصد فعلاً الجهة الرسمية.'))
                    break

    text = (p.path + ' ' + unquote(p.query)).lower()
    hits = [w for w in PHISH_WORDS if w in (host + ' ' + text)]
    if len(hits) >= 3:
        findings.append(_finding('medium', 'كلمات توحي بالتصيّد', 'تظهر كلمات مثل: ' + '، '.join(hits[:5]) + '. هذا وحده ليس دليلاً لكنه يستدعي الحذر.'))
    elif len(hits) == 2:
        findings.append(_finding('low', 'كلمات حساسة في الرابط', 'تظهر كلمات مثل: ' + '، '.join(hits) + '.'))

    path_l = p.path.lower()
    if path_l.endswith(RISKY_EXTENSIONS):
        findings.append(_finding('medium', 'الرابط يشير إلى ملف قابل للتنفيذ أو التثبيت', 'تنزيل ملفات مثل APK وEXE من مصدر غير موثوق طريقة شائعة لنشر البرمجيات الخبيثة.'))
    if port not in (None, 80, 443):
        findings.append(_finding('low', f'منفذ غير معتاد ({port})', 'المواقع العامة تستخدم عادة المنفذين 80 أو 443.'))
    if len(value) > 200:
        findings.append(_finding('low', 'رابط طويل جداً', 'الروابط الطويلة تُستخدم أحياناً لإخفاء الوجهة الحقيقية.'))
    try:
        q = parse_qs(p.query)
        for key, vals in q.items():
            if key.lower() in ('url', 'redirect', 'redirect_uri', 'next', 'goto', 'return', 'continue', 'dest', 'target') and any(re.match(r'https?://', v, re.I) for v in vals):
                findings.append(_finding('low', 'الرابط يحتوي وجهة توجيه أخرى', 'قد يعيد توجيهك إلى موقع مختلف بعد الفتح.'))
                break
    except Exception:
        pass
    if value.count('%') >= 10:
        findings.append(_finding('low', 'ترميز مكثّف في الرابط', 'كثرة الرموز المُرمّزة (%) قد تُخفي محتوى الرابط.'))

    score, level = risk_from_findings(findings)
    return {'normalized': value[:2048], 'host': host, 'findings': findings, 'score': score, 'risk': level}


# ---------------------------------------------------------------------------
# تحليل محتوى QR
# ---------------------------------------------------------------------------
URL_IN_TEXT_RE = re.compile(r'https?://[^\s\'"`<>)\]}\\]+', re.I)

RISK_ADVICE = {
    'high': 'خطورة عالية: لا تفتح المحتوى ولا تُدخل أي بيانات. إن وصلك الرمز من جهة تعرفها، تأكد منها عبر قناة أخرى.',
    'medium': 'توجد مؤشرات مقلقة: افحص الرابط عبر VirusTotal وراجع التفاصيل قبل أي خطوة.',
    'low': 'مؤشرات بسيطة فقط. تابع بحذر وتأكد من مصدر الرمز.',
    'none': 'لم تظهر مؤشرات محلية مقلقة، لكن هذا لا يضمن السلامة. افحص الرابط قبل فتحه.',
}


def _split_unescaped(s, sep=';'):
    out, cur, i = [], '', 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            cur += s[i + 1]
            i += 2
            continue
        if c == sep:
            out.append(cur)
            cur = ''
        else:
            cur += c
        i += 1
    out.append(cur)
    return out


def _qr_result(kind, label, findings, fields=None, url=None, urls=None):
    score, level = risk_from_findings(findings)
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f['severity'], 9))
    return {
        'type': kind, 'type_label': label, 'findings': findings, 'fields': fields or {},
        'url': url, 'urls': urls or ([url] if url else []), 'score': score, 'risk': level,
        'advice': RISK_ADVICE[level],
    }


def analyze_qr(text):
    t = (text or '').strip()
    if not t:
        raise ValueError('لا يوجد محتوى لتحليله.')
    if len(t) > 4096:
        raise ValueError('محتوى QR طويل جداً.')
    low = t.lower()

    # 1) مخططات خطيرة
    m = re.match(r'^(javascript|data|vbscript|file):', low)
    if m:
        loc = analyze_url_local(t)
        return _qr_result('dangerous', 'محتوى تنفيذي خطير', loc['findings'], {'المحتوى': t[:200]})

    # 2) شبكة Wi-Fi
    if low.startswith('wifi:'):
        kv = {}
        for part in _split_unescaped(t[5:]):
            if ':' in part:
                k, v = part.split(':', 1)
                kv[k.upper()] = v
        enc = (kv.get('T') or '').upper()
        pwd = kv.get('P', '')
        findings = [_finding('low', 'اتصال بشبكة لا تعرف مصدرها', 'نقاط الاتصال الخبيثة قد تراقب حركة الإنترنت. اتصل فقط إذا كنت واثقاً أنها شبكة المكان الذي أنت فيه.')]
        if enc in ('NOPASS', '') and not pwd:
            findings.append(_finding('medium', 'شبكة مفتوحة بلا كلمة مرور', 'الاتصال غير مشفّر ويمكن لأي شخص قريب التجسس عليه.'))
        elif enc == 'WEP':
            findings.append(_finding('medium', 'تشفير WEP قديم', 'WEP ضعيف ويمكن كسره بسهولة.'))
        fields = {'اسم الشبكة': kv.get('S', '—'), 'التشفير': enc or 'غير محدد', 'كلمة المرور': ('•' * min(len(pwd), 12) + f' ({len(pwd)} حرفاً)') if pwd else 'لا توجد',
                  'شبكة مخفية': 'نعم' if kv.get('H', '').lower() == 'true' else 'لا'}
        return _qr_result('wifi', 'شبكة Wi-Fi', findings, fields)

    # 3) بطاقة اتصال
    if low.startswith('begin:vcard'):
        fields, urls = {}, []
        for line in t.splitlines():
            ul = line.upper()
            if ul.startswith('FN:'):
                fields['الاسم'] = line[3:].strip()
            elif ul.startswith('TEL'):
                fields['الهاتف'] = line.split(':', 1)[-1].strip()
            elif ul.startswith('EMAIL'):
                fields['البريد'] = line.split(':', 1)[-1].strip()
            elif ul.startswith('ORG:'):
                fields['الجهة'] = line[4:].strip()
            elif ul.startswith('URL'):
                u = line.split(':', 1)[-1].strip()
                if u:
                    urls.append(u)
                    fields['الموقع'] = u
        findings = [_finding('info', 'بطاقة اتصال', 'ستُضاف جهة اتصال إلى هاتفك. راجع البيانات قبل الحفظ.')]
        url = None
        if urls:
            loc = analyze_url_local(urls[0])
            findings += loc['findings']
            url = loc['normalized']
        return _qr_result('vcard', 'بطاقة جهة اتصال', findings, fields, url, urls[:3])

    # 4) بريد
    if low.startswith('mailto:'):
        p = urlparse(t)
        q = parse_qs(p.query)
        fields = {'المستلم': unquote(p.path), 'الموضوع': (q.get('subject') or ['—'])[0][:120]}
        findings = [_finding('info', 'سيُفتح تطبيق البريد', 'رسالة جاهزة قد تحتوي نصاً صاغه المهاجم. راجعها قبل الإرسال.')]
        body = (q.get('body') or [''])[0]
        if body:
            fields['النص'] = body[:200]
            if URL_IN_TEXT_RE.search(body):
                findings.append(_finding('medium', 'نص الرسالة يحتوي رابطاً', 'قد يدفعك لإرسال رسالة تتضمن رابطاً ضاراً.'))
        body_urls = URL_IN_TEXT_RE.findall(body)
        return _qr_result('email', 'بريد إلكتروني', findings, fields, body_urls[0] if body_urls else None, body_urls[:3])

    # 5) اتصال أو رسائل
    if low.startswith('tel:'):
        findings = [_finding('low', 'اتصال هاتفي', 'تأكد من الرقم قبل الاتصال؛ الأرقام المميزة الدولية قد تُحمّل رسوماً مرتفعة.')]
        return _qr_result('phone', 'رقم هاتف', findings, {'الرقم': t[4:60]})
    if re.match(r'^(sms|smsto|mms|mmsto):', low):
        rest = t.split(':', 1)[1]
        number, _, body = rest.partition(':') if low.startswith(('smsto', 'mmsto')) else rest.partition('?body=')
        findings = [_finding('low', 'رسالة نصية جاهزة', 'قد تشترك بخدمة مدفوعة بمجرد الإرسال. راجع الرقم والنص.')]
        fields = {'الرقم': number[:40], 'النص': body[:200] or '—'}
        if URL_IN_TEXT_RE.search(body):
            findings.append(_finding('medium', 'النص يحتوي رابطاً', 'قد يدفعك لإرسال رابط ضار إلى جهات اتصالك.'))
        body_urls = URL_IN_TEXT_RE.findall(body)
        return _qr_result('sms', 'رسالة نصية', findings, fields, body_urls[0] if body_urls else None, body_urls[:3])

    # 6) موقع جغرافي
    if low.startswith('geo:'):
        return _qr_result('geo', 'موقع جغرافي', [_finding('info', 'إحداثيات', 'سيُفتح تطبيق الخرائط على هذا الموقع.')], {'الإحداثيات': t[4:80]})

    # 7) مصادقة ثنائية
    if low.startswith('otpauth://') or low.startswith('otpauth-migration://'):
        findings = [_finding('medium', 'يحتوي مفتاح مصادقة ثنائية', 'هذا الرمز يمنح تطبيقاً قدرة توليد رموز دخول حسابك. امسحه فقط في تطبيق المصادقة الخاص بك، وفقط إن طلبته أنت من خدمة تثق بها.')]
        return _qr_result('otp', 'إعداد مصادقة ثنائية', findings, {})

    # 8) تطبيقات أندرويد
    if low.startswith('intent://') or low.startswith('market://'):
        sev = 'high' if low.startswith('intent://') else 'medium'
        findings = [_finding(sev, 'يفتح تطبيقاً أو متجراً على هاتفك', 'قد يشغّل تطبيقاً بإعدادات يحددها المهاجم أو يدفعك لتثبيت تطبيق غير معروف.')]
        return _qr_result('intent', 'رابط تطبيق أندرويد', findings, {'المحتوى': t[:200]})

    # 9) دفع وعملات رقمية
    if re.match(r'^(bitcoin|ethereum|litecoin|monero|upi|bitcoincash|tron):', low) or t.startswith('000201'):
        findings = [_finding('medium', 'رمز دفع', 'تأكد من هوية المستلم والمبلغ قبل التحويل. عمليات التحويل غالباً لا يمكن استرجاعها.')]
        return _qr_result('payment', 'رمز دفع / عملات رقمية', findings, {'المحتوى': t[:140]})

    # 10) رابط ويب
    if re.match(r'^https?://', low) or (BARE_DOMAIN_RE.match(t) and ' ' not in t):
        loc = analyze_url_local(t)
        findings = list(loc['findings'])
        if not any(f['severity'] != 'info' for f in findings):
            findings.append(_finding('info', 'لم تظهر مؤشرات محلية مقلقة', 'الفحص المحلي يعتمد على شكل الرابط فقط. افحصه عبر VirusTotal لرأي المحركات.'))
        res = _qr_result('url', 'رابط ويب', findings, {'العنوان': loc['normalized'], 'الموقع': loc['host']}, loc['normalized'])
        return res

    # 11) نص عادي (وقد يحتوي روابط)
    urls = URL_IN_TEXT_RE.findall(t)
    findings = []
    url = None
    if urls:
        loc = analyze_url_local(urls[0])
        findings.append(_finding('low', 'النص يحتوي رابطاً', 'وُجد رابط داخل النص، وسيُحلَّل الأول منه.'))
        findings += loc['findings']
        url = loc['normalized']
    else:
        findings.append(_finding('info', 'نص عادي', 'لا يحتوي رابطاً أو أمراً ظاهراً.'))
    return _qr_result('text', 'نص عادي', findings, {'النص': t[:300]}, url, urls[:3])


# ---------------------------------------------------------------------------
# التحليل الثابت للأكواد
# ---------------------------------------------------------------------------
LANG_LABELS = {
    'python': 'Python', 'javascript': 'JavaScript / TypeScript', 'php': 'PHP', 'java': 'Java',
    'c': 'C / C++', 'csharp': 'C#', 'shell': 'Shell / Bash', 'powershell': 'PowerShell',
    'sql': 'SQL', 'html': 'HTML', 'general': 'عام / غير محدد',
}
LANG_DETECT = {
    'python': [r'^\s*def \w+\(', r'^\s*import \w+', r'^\s*from [\w.]+ import', r'\bself\b', r'\belif\b', r'^\s*class \w+.*:\s*$', r'\bprint\(', r'__name__'],
    'javascript': [r'\bconst \w+\s*=', r'\blet \w+\s*=', r'=>', r'\bfunction\s*\w*\s*\(', r'console\.log', r'\brequire\(', r'\bdocument\.', r'\bwindow\.', r'\bimport .* from '],
    'php': [r'<\?php', r'\$\w+\s*=', r'\becho\b', r'->\w+', r'\$_(GET|POST|REQUEST|SERVER)'],
    'java': [r'\bpublic\s+(static\s+)?(class|void|int|String)', r'System\.out', r'^\s*import java', r'\bprivate\s+\w+\s+\w+;'],
    'c': [r'#include\s*[<"]', r'\bint\s+main\s*\(', r'\bprintf\s*\(', r'\bmalloc\s*\(', r'std::'],
    'csharp': [r'\busing System', r'\bnamespace\s+\w+', r'Console\.Write', r'\bpublic\s+(static\s+)?(class|void|string)\b'],
    'shell': [r'^#!/bin/(ba|z)?sh', r'^\s*fi\s*$', r'\$\(', r'\bthen\s*$', r'^\s*echo\b', r'\bsudo\b'],
    'powershell': [r'\bGet-\w+', r'\bWrite-Host', r'-ExecutionPolicy', r'\$\w+\s*=\s*New-Object', r'\bInvoke-\w+', r'\bIEX\b'],
    'sql': [r'\bSELECT\b[^;]{1,200}?\bFROM\b', r'\bINSERT\s+INTO\b', r'\bCREATE\s+TABLE\b', r'\bUPDATE\b\s+\w+\s+SET\b', r'\bDROP\s+TABLE\b'],
    'html': [r'<!doctype html', r'<html', r'<script', r'<div', r'<body'],
}
LANG_GROUPS = {'html': {'html', 'javascript'}, 'javascript': {'javascript'}}

PLACEHOLDER_HINTS = ('your', 'example', 'placeholder', 'changeme', 'change_me', 'xxxx', '****', '<', '>', '${', '{{', 'todo', 'dummy', 'sample', 'secret_here', 'password')


def detect_language(code):
    code = code[:20000]  # عينة كافية للكشف وتمنع بطء الأنماط على المدخلات الضخمة
    head = code.lstrip()[:200]
    if re.match(r'#!.*\b(?:ba|z|da|k)?sh\b', head):
        return 'shell'
    if re.match(r'#!.*\bpython', head):
        return 'python'
    if re.match(r'#!.*\bnode\b', head):
        return 'javascript'
    if head.lower().startswith('<?php'):
        return 'php'
    if re.match(r'<!doctype html|<html', head, re.I):
        return 'html'
    scores = {}
    for lang, pats in LANG_DETECT.items():
        s = 0
        for pat in pats:
            if re.search(pat, code, re.M | re.I if lang in ('sql',) else re.M):
                s += 1
        scores[lang] = s
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else 'general'


def _secret_value_ok(line, m):
    val = m.group(m.lastindex or 0).lower() if m.lastindex else ''
    if not val:
        return True
    if any(h in val for h in PLACEHOLDER_HINTS if h != 'password') or val in ('password', 'secret', 'token'):
        return False
    return True


def _is_public_ip(line, m):
    ip = m.group(0)
    try:
        parts = [int(x) for x in ip.split('.')]
        if any(p > 255 for p in parts):
            return False
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_unspecified or obj.is_multicast or obj.is_reserved or obj.is_link_local:
            return False
        if parts[0] == 0 or ip.startswith('255.'):
            return False
        return True
    except ValueError:
        return False


def _weak_random_ctx(line, m):
    return bool(re.search(r'token|secret|password|passwd|session|otp|nonce|salt|key|csrf', line, re.I))


def _rule(rid, title, sev, pattern, desc, fix, cwe=None, langs=None, mask=False, flags=0, check=None, group=None, allow_comment=False):
    return {'id': rid, 'title': title, 'severity': sev, 're': re.compile(pattern, flags), 'desc': desc, 'fix': fix,
            'cwe': cwe, 'langs': set(langs) if langs else None, 'mask': mask, 'check': check, 'group': group or rid,
            'allow_comment': allow_comment}


SQLI_DESC = 'بناء استعلام SQL بدمج نصوص أو متغيرات يسمح للمهاجم بحقن أوامر في الاستعلام وقراءة البيانات أو تعديلها.'
SQLI_FIX = 'استخدم استعلامات مُهيّأة (Parameterized Queries / Prepared Statements) ولا تدمج مدخلات المستخدم داخل نص الاستعلام.'
XSS_DESC = 'إدراج نص غير مُعقَّم داخل الصفحة قد يسمح بتنفيذ سكربت المهاجم في متصفح الضحية.'
XSS_FIX = 'استخدم textContent بدل innerHTML، أو عقّم المدخلات بمكتبة موثوقة (مثل DOMPurify) واستخدم ترميز المخرجات.'
CMD_DESC = 'تمرير مدخلات غير موثوقة إلى أوامر النظام قد يمكّن المهاجم من تنفيذ أوامر على الخادم.'
CMD_FIX = 'تجنب استدعاء الشل. استخدم واجهات تأخذ قائمة وسائط (shell=False) وتحقق من المدخلات بقائمة سماح.'
EVAL_DESC = 'تنفيذ نص كأنه كود يعني أن أي نص يصل إليه المهاجم قد يتحول إلى تنفيذ كود عشوائي.'
EVAL_FIX = 'أزل eval/exec واستبدلها بمنطق مباشر أو تحليل آمن للبيانات (مثل JSON.parse أو ast.literal_eval).'
SECRET_FIX = 'انقل الأسرار إلى متغيرات بيئة أو مدير أسرار، وأعد توليد أي سر ظهر في الكود لأنه يُعتبر مكشوفاً.'
DESER_DESC = 'فك تسلسل بيانات غير موثوقة قد يؤدي إلى تنفيذ كود عن بُعد.'
DESER_FIX = 'لا تفك تسلسل بيانات من مصدر غير موثوق. استخدم صيغاً آمنة مثل JSON مع تحقق من البنية.'
HASH_DESC = 'خوارزمية تجزئة ضعيفة وقابلة للاصطدام ولا تصلح لحماية كلمات المرور أو التوقيعات.'
HASH_FIX = 'استخدم bcrypt أو scrypt أو Argon2 لكلمات المرور، وSHA-256 أو أقوى للتجزئة العامة.'
TLS_DESC = 'تعطيل التحقق من الشهادة يجعل الاتصال عرضة لهجمات الوسيط (MITM).'
TLS_FIX = 'أبقِ التحقق مفعلاً، وإن لزم استخدم شهادة موثوقة أو أضف الشهادة الجذرية المطلوبة بدل تعطيل الفحص.'

RULES = [
    # ---- حقن SQL ----
    _rule('sqli-py', 'احتمال حقن SQL', 'high', r'\.execute\w*\(\s*(?:f["\']|["\'][^"\']*["\']\s*(?:%|\+)|["\'][^"\']*["\']\.format)', SQLI_DESC, SQLI_FIX, 'CWE-89', ['python'], group='sqli'),
    _rule('sqli-js', 'احتمال حقن SQL', 'high', r'\.(?:query|execute|raw)\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\']\s*\+)', SQLI_DESC, SQLI_FIX, 'CWE-89', ['javascript'], group='sqli'),
    _rule('sqli-php', 'احتمال حقن SQL', 'high', r'(?:mysqli?_query|->query|->exec)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|["\']\s*\.\s*\$)', SQLI_DESC, SQLI_FIX, 'CWE-89', ['php'], group='sqli'),
    _rule('sqli-php2', 'احتمال حقن SQL', 'high', r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\$\w+', SQLI_DESC, SQLI_FIX, 'CWE-89', ['php'], flags=re.I, group='sqli'),
    _rule('sqli-java', 'احتمال حقن SQL', 'high', r'(?:executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery)\(\s*"[^"]*"\s*\+', SQLI_DESC, SQLI_FIX, 'CWE-89', ['java'], group='sqli'),
    _rule('sqli-cs', 'احتمال حقن SQL', 'high', r'new\s+(?:Sql|MySql|Npgsql)Command\(\s*(?:\$"|"[^"]*"\s*\+)', SQLI_DESC, SQLI_FIX, 'CWE-89', ['csharp'], group='sqli'),
    _rule('sqli-gen', 'احتمال حقن SQL', 'high', r'["\'`]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\'`]*["\'`]\s*(?:\+|\.|%)\s*\w+', SQLI_DESC, SQLI_FIX, 'CWE-89', flags=re.I, group='sqli'),

    # ---- تنفيذ كود / أوامر ----
    _rule('eval-py', 'استخدام eval / exec', 'high', r'(?<![.\w])(?:eval|exec)\s*\(', EVAL_DESC, EVAL_FIX, 'CWE-95', ['python'], group='eval'),
    _rule('eval-js', 'استخدام eval / Function', 'high', r'(?<![.\w])eval\s*\(|new\s+Function\s*\(', EVAL_DESC, EVAL_FIX, 'CWE-95', ['javascript'], group='eval'),
    _rule('eval-timer', 'مؤقت يُنفّذ نصاً كأنه كود', 'medium', r'set(?:Timeout|Interval)\s*\(\s*["\'`]', EVAL_DESC, 'مرّر دالة بدل النص إلى setTimeout/setInterval.', 'CWE-95', ['javascript']),
    _rule('eval-php', 'استخدام eval / assert', 'high', r'(?<![.\w>$])(?:eval|assert|create_function)\s*\(', EVAL_DESC, EVAL_FIX, 'CWE-95', ['php'], group='eval'),
    _rule('eval-ps', 'تنفيذ نص كأمر (Invoke-Expression)', 'high', r'\b(?:Invoke-Expression|IEX)\b', EVAL_DESC, EVAL_FIX, 'CWE-95', ['powershell', 'general']),
    _rule('cmd-py', 'تنفيذ أوامر نظام', 'high', r'\bos\.(?:system|popen)\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True', CMD_DESC, CMD_FIX, 'CWE-78', ['python'], group='cmd'),
    _rule('cmd-js', 'تنفيذ أوامر نظام', 'high', r'\b(?:cp|child_process|childProcess)\.exec(?:Sync)?\s*\(', CMD_DESC, CMD_FIX, 'CWE-78', ['javascript'], group='cmd'),
    _rule('cmd-php', 'تنفيذ أوامر نظام', 'high', r'(?<![.\w>$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(', CMD_DESC, CMD_FIX, 'CWE-78', ['php'], group='cmd'),
    _rule('cmd-java', 'تنفيذ أوامر نظام', 'high', r'Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(', CMD_DESC, CMD_FIX, 'CWE-78', ['java'], group='cmd'),
    _rule('cmd-c', 'تنفيذ أوامر نظام', 'high', r'(?<![.\w>])(?:system|popen)\s*\(', CMD_DESC, CMD_FIX, 'CWE-78', ['c'], group='cmd'),
    _rule('cmd-cs', 'تشغيل عملية خارجية', 'medium', r'Process\.Start\s*\(', CMD_DESC, CMD_FIX, 'CWE-78', ['csharp'], group='cmd'),
    _rule('cmd-sh-eval', 'استخدام eval في الشل', 'high', r'(?<![\w.-])eval\s+["\'$`]', EVAL_DESC, EVAL_FIX, 'CWE-78', ['shell']),

    # ---- XSS ----
    _rule('xss-inner', 'كتابة HTML مباشرة في الصفحة', 'medium', r'\.(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML', XSS_DESC, XSS_FIX, 'CWE-79', ['javascript']),
    _rule('xss-jq', 'استخدام html() مع نص متغير', 'low', r'\$\([^)]*\)\.html\(\s*[^\s\'")]', XSS_DESC, XSS_FIX, 'CWE-79', ['javascript']),
    _rule('xss-php', 'طباعة مدخلات المستخدم دون تعقيم', 'high', r'\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)', XSS_DESC, 'استخدم htmlspecialchars($v, ENT_QUOTES, "UTF-8") قبل الطباعة.', 'CWE-79', ['php']),
    _rule('xss-py', 'تعطيل التعقيم التلقائي للقوالب', 'medium', r'\|\s*safe\b|\bMarkup\s*\(|render_template_string\s*\(', XSS_DESC, XSS_FIX, 'CWE-79', ['python']),

    # ---- تضمين ملفات / مسارات ----
    _rule('lfi-php', 'تضمين ملف يعتمد على مدخلات المستخدم', 'high', r'\b(?:include|require)(?:_once)?\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)', 'قد يسمح بقراءة أو تنفيذ ملفات غير مقصودة (LFI/RFI).', 'استخدم قائمة سماح بأسماء الملفات ولا تمرر مدخلات المستخدم مباشرة.', 'CWE-98', ['php']),
    _rule('path-py', 'فتح ملف بمسار من الطلب', 'medium', r'\bopen\s*\([^)]*request\.(?:args|form|values|json|GET|POST)', 'مسار ملف قادم من المستخدم قد يسمح بقراءة ملفات خارج المجلد المقصود (Path Traversal).', 'نظّف المسار بـ os.path.basename أو secure_filename وتحقق أنه داخل المجلد المسموح.', 'CWE-22', ['python']),
    _rule('path-js', 'قراءة ملف بمسار من الطلب', 'medium', r'(?:readFile|readFileSync|sendFile|createReadStream)\s*\([^)]*req\.(?:query|params|body)', 'مسار ملف قادم من المستخدم قد يسمح بقراءة ملفات خارج المجلد المقصود (Path Traversal).', 'استخدم path.basename وتحقق أن المسار النهائي يقع داخل المجلد المسموح.', 'CWE-22', ['javascript']),
    _rule('upload-php', 'رفع ملفات', 'medium', r'move_uploaded_file\s*\(', 'الملفات المرفوعة بلا تحقق قد تتضمن سكربتات تنفيذية.', 'تحقق من الامتداد والنوع الحقيقي والحجم، وغيّر الاسم، وخزّن الملف خارج مجلد الويب.', 'CWE-434', ['php']),
    _rule('extract-php', 'استخدام extract على مدخلات المستخدم', 'high', r'\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', 'يسمح للمستخدم بكتابة فوق متغيرات البرنامج.', 'اقرأ القيم المطلوبة بأسمائها فقط.', 'CWE-621', ['php']),

    # ---- فك التسلسل ----
    _rule('deser-py', 'فك تسلسل غير آمن', 'high', r'\b(?:c?[pP]ickle|marshal)\.loads?\s*\(|\byaml\.load\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)', DESER_DESC, DESER_FIX, 'CWE-502', ['python']),
    _rule('deser-php', 'فك تسلسل غير آمن', 'high', r'\bunserialize\s*\(', DESER_DESC, DESER_FIX, 'CWE-502', ['php']),
    _rule('deser-java', 'فك تسلسل غير آمن', 'high', r'new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)', DESER_DESC, DESER_FIX, 'CWE-502', ['java']),
    _rule('deser-cs', 'فك تسلسل غير آمن', 'high', r'\b(?:BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter)\b', DESER_DESC, DESER_FIX, 'CWE-502', ['csharp']),
    _rule('deser-js', 'فك تسلسل غير آمن', 'high', r'node-serialize|serialize\.unserialize', DESER_DESC, DESER_FIX, 'CWE-502', ['javascript']),

    # ---- تشفير ضعيف ----
    _rule('hash-py', 'خوارزمية تجزئة ضعيفة', 'medium', r'hashlib\.(?:md5|sha1)\s*\(|hashlib\.new\(\s*["\'](?:md5|sha1)', HASH_DESC, HASH_FIX, 'CWE-327', ['python'], group='hash'),
    _rule('hash-js', 'خوارزمية تجزئة ضعيفة', 'medium', r'createHash\(\s*["\'](?:md5|sha1)["\']\s*\)', HASH_DESC, HASH_FIX, 'CWE-327', ['javascript'], group='hash'),
    _rule('hash-php', 'خوارزمية تجزئة ضعيفة', 'medium', r'(?<![.\w>$])(?:md5|sha1)\s*\(', HASH_DESC, HASH_FIX, 'CWE-327', ['php'], group='hash'),
    _rule('hash-java', 'خوارزمية تجزئة ضعيفة', 'medium', r'getInstance\(\s*"(?:MD5|SHA-?1)"', HASH_DESC, HASH_FIX, 'CWE-327', ['java'], group='hash'),
    _rule('hash-cs', 'خوارزمية تجزئة ضعيفة', 'medium', r'\b(?:MD5|SHA1)(?:CryptoServiceProvider|\.Create)\b', HASH_DESC, HASH_FIX, 'CWE-327', ['csharp'], group='hash'),
    _rule('cipher-weak', 'تشفير قديم أو وضع ECB', 'medium', r'\b(?:DES|3DES|RC4|RC2)\b|MODE_ECB|/ECB/|AES/ECB', 'خوارزميات قديمة أو وضع ECB يكشف أنماط البيانات ولا يوفر حماية كافية.', 'استخدم AES-GCM أو ChaCha20-Poly1305 مع مفتاح وIV مناسبين.', 'CWE-327', check=lambda l, m: not re.search(r'\bdescription\b|\bdes\s*=', l, re.I)),
    _rule('rand-py', 'مولّد أرقام عشوائية غير آمن لأغراض أمنية', 'medium', r'\brandom\.(?:random|randint|choice|randrange|getrandbits)\s*\(', 'مولدات random العادية قابلة للتنبؤ ولا تصلح للرموز وكلمات المرور.', 'استخدم وحدة secrets في بايثون.', 'CWE-338', ['python'], check=_weak_random_ctx),
    _rule('rand-js', 'مولّد أرقام عشوائية غير آمن لأغراض أمنية', 'medium', r'Math\.random\s*\(', 'Math.random قابل للتنبؤ ولا يصلح للرموز والمفاتيح.', 'استخدم crypto.getRandomValues أو crypto.randomBytes.', 'CWE-338', ['javascript'], check=_weak_random_ctx),
    _rule('rand-java', 'مولّد أرقام عشوائية غير آمن لأغراض أمنية', 'medium', r'new\s+Random\s*\(', 'java.util.Random قابل للتنبؤ.', 'استخدم SecureRandom.', 'CWE-338', ['java'], check=_weak_random_ctx),

    # ---- تعطيل TLS ----
    _rule('tls-py', 'تعطيل التحقق من شهادة TLS', 'high', r'verify\s*=\s*False|_create_unverified_context|CERT_NONE', TLS_DESC, TLS_FIX, 'CWE-295', ['python'], group='tls'),
    _rule('tls-js', 'تعطيل التحقق من شهادة TLS', 'high', r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0', TLS_DESC, TLS_FIX, 'CWE-295', ['javascript'], group='tls'),
    _rule('tls-php', 'تعطيل التحقق من شهادة TLS', 'high', r'CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)', TLS_DESC, TLS_FIX, 'CWE-295', ['php'], group='tls'),
    _rule('tls-java', 'قبول أي شهادة TLS', 'high', r'ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|NoopHostnameVerifier|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}', TLS_DESC, TLS_FIX, 'CWE-295', ['java'], group='tls'),
    _rule('tls-cs', 'قبول أي شهادة TLS', 'high', r'ServerCertificateValidationCallback\s*[+]?=.*(?:true|=>)|DangerousAcceptAnyServerCertificateValidator', TLS_DESC, TLS_FIX, 'CWE-295', ['csharp'], group='tls'),
    _rule('tls-sh', 'تعطيل التحقق من الشهادة في curl/wget', 'medium', r'\bcurl\b[^|\n]*\s(?:-k|--insecure)\b|\bwget\b[^|\n]*--no-check-certificate', TLS_DESC, TLS_FIX, 'CWE-295', ['shell']),

    # ---- إعدادات خطرة ----
    _rule('debug-py', 'وضع التصحيح (Debug) مفعّل', 'medium', r'\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b', 'تفعيل Debug في بيئة الإنتاج قد يكشف مسارات وأسراراً أو يتيح تنفيذ كود (كما في Werkzeug).', 'عطّل Debug في الإنتاج واجعله يعتمد على متغير بيئة.', 'CWE-489', ['python']),
    _rule('csrf-off', 'تعطيل حماية CSRF', 'medium', r'csrf_exempt|csrf\(\)\.disable|WTF_CSRF_ENABLED\s*=\s*False|csrf\.disable\(', 'تعطيل الحماية يسمح بتنفيذ طلبات نيابة عن المستخدم دون علمه.', 'أبقِ حماية CSRF مفعلة واستخدم رموزاً لكل نموذج.', 'CWE-352'),
    _rule('cors-any', 'السماح لأي موقع بالوصول (CORS *)', 'low', r'Access-Control-Allow-Origin["\']?\s*[:,=]\s*["\']?\*|origins?\s*[:=]\s*["\']\*["\']', 'يسمح لأي موقع بقراءة الاستجابات، وهو خطر مع البيانات الحساسة.', 'حدّد المواقع المسموحة بدقة.', 'CWE-942'),
    _rule('jwt-none', 'قبول توقيع JWT بخوارزمية none', 'high', r'["\']?alg["\']?\s*[:=]\s*["\']none["\']', 'خوارزمية none تلغي التوقيع وتسمح بتزوير الرموز.', 'ثبّت الخوارزمية المقبولة ورفض none صراحة.', 'CWE-347'),
    _rule('perm-777', 'صلاحيات 777', 'medium', r'\bchmod\s+(?:-R\s+)?0?777\b|0o?777\b', 'منح الجميع صلاحية القراءة والكتابة والتنفيذ يفتح الباب للتلاعب بالملفات.', 'امنح أقل صلاحيات لازمة (مثل 640 أو 750).', 'CWE-732'),
    _rule('rm-root', 'حذف مسار جذري', 'high', r'\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+/(?:\s|\*|$)', 'قد يحذف النظام بالكامل.', 'تحقق من المتغيرات قبل الحذف وتجنب المسارات الجذرية.', 'CWE-73', ['shell', 'general']),
    _rule('tmp-py', 'ملف مؤقت غير آمن', 'low', r'tempfile\.mktemp\s*\(', 'mktemp عرضة لسباق الملفات (Race Condition).', 'استخدم tempfile.mkstemp أو NamedTemporaryFile.', 'CWE-377', ['python']),
    _rule('mysql-old', 'دوال MySQL قديمة', 'low', r'\bmysql_(?:query|connect|fetch_\w+)\s*\(', 'الدوال محذوفة من PHP الحديث ولا تدعم الاستعلامات المهيّأة.', 'انتقل إلى PDO أو mysqli مع Prepared Statements.', 'CWE-89', ['php']),

    # ---- ثغرات الذاكرة (C/C++) ----
    _rule('c-gets', 'استخدام gets', 'high', r'(?<![.\w])gets\s*\(', 'gets لا يتحقق من الطول وقد يسبب تجاوز مخزن مؤقت، وقد أُزيلت من المعيار.', 'استخدم fgets مع حجم المخزن.', 'CWE-242', ['c']),
    _rule('c-unsafe', 'دالة نسخ نصوص غير آمنة', 'medium', r'(?<![.\w])(?:strcpy|strcat|sprintf|vsprintf)\s*\(', 'لا تتحقق من حجم الوجهة وقد تسبب تجاوز مخزن مؤقت.', 'استخدم strncpy / snprintf / strlcpy مع حدود واضحة.', 'CWE-120', ['c']),
    _rule('c-scanf', 'قراءة نص دون حد', 'medium', r'scanf\s*\(\s*"[^"]*%s', 'قراءة %s دون تحديد عرض قد تتجاوز المخزن.', 'حدد العرض مثل %63s أو استخدم fgets.', 'CWE-120', ['c']),
    _rule('c-fmt', 'احتمال ثغرة سلسلة التنسيق', 'medium', r'(?<![.\w])printf\s*\(\s*[A-Za-z_]\w*\s*\)', 'تمرير متغير كسلسلة تنسيق قد يسمح بقراءة أو كتابة الذاكرة.', 'استخدم printf("%s", var).', 'CWE-134', ['c']),

    # ---- أسرار مكشوفة ----
    _rule('secret-hard', 'بيانات اعتماد مكتوبة داخل الكود', 'high',
          r'\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|access[_-]?key|client[_-]?secret|private[_-]?key)\b["\']?\s*[:=]\s*["\']([^"\'\s]{6,})["\']',
          'وجود كلمة مرور أو مفتاح داخل الكود يعني أن كل من يرى الكود (أو سجل Git) يستطيع استخدامه.', SECRET_FIX, 'CWE-798', mask=True, flags=re.I, check=_secret_value_ok, allow_comment=True),
    _rule('secret-aws', 'مفتاح AWS ظاهر', 'high', r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', 'مفاتيح AWS المسرّبة تُستغل خلال دقائق بعد النشر.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-gh', 'رمز GitHub ظاهر', 'high', r'\bgh[pousr]_[A-Za-z0-9]{30,}\b', 'الرمز يمنح صلاحيات على المستودعات.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-slack', 'رمز Slack ظاهر', 'high', r'\bxox[baprs]-[A-Za-z0-9-]{10,}', 'الرمز يمنح صلاحيات على مساحة العمل.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-google', 'مفتاح Google API ظاهر', 'high', r'\bAIza[0-9A-Za-z_-]{35}\b', 'المفتاح قد يُستخدم على حسابك ويسبب تكاليف.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-stripe', 'مفتاح Stripe سري ظاهر', 'high', r'\bsk_live_[0-9a-zA-Z]{16,}\b', 'يتيح تنفيذ عمليات مالية.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-pem', 'مفتاح خاص (Private Key) ظاهر', 'high', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY', 'المفتاح الخاص يجب ألا يظهر في الكود أبداً.', SECRET_FIX, 'CWE-321', allow_comment=True),
    _rule('secret-jwt', 'رمز JWT ظاهر', 'medium', r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}', 'قد يكون رمز جلسة صالحاً.', SECRET_FIX, 'CWE-798', mask=True, allow_comment=True),
    _rule('secret-conn', 'سلسلة اتصال تحتوي كلمة مرور', 'high', r'\b[a-z][a-z0-9+.-]*://[^/\s:@\'"]+:([^@\s\'"]{3,})@', 'بيانات الدخول مضمّنة في عنوان الاتصال.', SECRET_FIX, 'CWE-798', mask=True, flags=re.I, check=_secret_value_ok, allow_comment=True),

    # ---- مؤشرات برمجيات خبيثة وتعتيم ----
    _rule('mal-revshell', 'نمط شل عكسي (Reverse Shell)', 'high', r'/dev/tcp/\d|bash\s+-i\s*>&|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s|pty\.spawn\s*\(|os\.dup2\s*\(\s*\w+\.fileno', 'هذه الأنماط تفتح قناة تحكم عن بُعد من جهازك إلى المهاجم.', 'إن لم تكتبه بنفسك فاعتبر الكود خبيثاً ولا تشغّله. راجع مصدره.', 'CWE-506', allow_comment=True),
    _rule('mal-dl-exec', 'تنزيل وتنفيذ مباشر', 'high', r'\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b', 'تشغيل سكربت من الإنترنت دون مراجعته يمنح مصدره تحكماً كاملاً.', 'نزّل الملف أولاً وراجعه وتحقق من البصمة (hash) قبل التشغيل.', 'CWE-494', allow_comment=True),
    _rule('mal-ps-enc', 'PowerShell بأوامر مشفّرة أو مخفية', 'high', r'\bpowershell(?:\.exe)?\b[^\n]*\s-(?:enc|encodedcommand|e)\s|-(?:WindowStyle\s+Hidden|w\s+hidden)|-ExecutionPolicy\s+Bypass|DownloadString|DownloadFile|Net\.WebClient', 'مزيج شائع في برمجيات التحميل والتنفيذ الخبيثة.', 'راجع مصدر الكود. لا تشغّل أوامر مشفّرة لا تفهمها.', 'CWE-506', ['powershell', 'shell', 'general', 'csharp'], flags=re.I, allow_comment=True),
    _rule('mal-miner', 'مؤشرات تعدين عملات رقمية', 'high', r'stratum\+tcp://|\bxmrig\b|coinhive|cryptonight|\bminergate\b', 'قد يستهلك موارد الجهاز لصالح طرف آخر.', 'تأكد أن التعدين مقصود ومعلن، وإلا فاحذف الكود.', 'CWE-506', flags=re.I, allow_comment=True),
    _rule('mal-keylog', 'مؤشرات تسجيل ضغطات لوحة المفاتيح', 'medium', r'GetAsyncKeyState|SetWindowsHookEx|\bpynput\b|keyboard\.on_press|\bkeylog', 'قد تُستخدم لسرقة كلمات المرور.', 'تأكد من مشروعية الاستخدام وموافقة المستخدم.', 'CWE-200', flags=re.I, allow_comment=True),
    _rule('mal-persist', 'مؤشرات بقاء دائم في النظام', 'low', r'\bschtasks\b|\bcrontab\b|CurrentVersion\\Run|/etc/rc\.local|systemctl\s+enable', 'تُستخدم لجعل البرنامج يعمل بعد إعادة التشغيل، وقد تكون مشروعة في المثبّتات.', 'تأكد أن هذا السلوك مقصود وموثّق.', 'CWE-506', flags=re.I),
    _rule('obf-b64-call', 'فك ترميز Base64 أثناء التشغيل', 'low', r'\b(?:atob|base64_decode|b64decode|FromBase64String|Base64\.getDecoder)\s*\(?', 'فك الترميز قد يُخفي حمولة، ويكون خطيراً إذا أُتبع بتنفيذ.', 'تحقق مما يُفك ترميزه وأين يُستخدم.', 'CWE-506'),
    _rule('obf-b64-blob', 'سلسلة طويلة مشفّرة (Base64)', 'medium', r'[A-Za-z0-9+/]{120,}={0,2}', 'السلاسل الطويلة قد تخفي حمولة أو ملفاً مضمّناً.', 'فك الترميز في بيئة معزولة وراجع المحتوى.', 'CWE-506'),
    _rule('obf-hex', 'ترميز Hex أو Unicode مكثّف', 'medium', r'(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}', 'تُستخدم لإخفاء النصوص عن القارئ وعن أدوات الفحص.', 'فك الترميز وراجع النص الناتج.', 'CWE-506'),
    _rule('obf-chr', 'بناء نص من أرقام (fromCharCode / chr)', 'medium', r'String\.fromCharCode\s*\((?:\s*\d+\s*,){6,}|(?:chr\(\s*\d+\s*\)\s*[.+]\s*){5,}', 'أسلوب تعتيم معروف لإخفاء أوامر أو روابط.', 'حوّل الأرقام إلى نص وراجعه.', 'CWE-506'),
    _rule('ip-hard', 'عنوان IP عام مكتوب في الكود', 'low', r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', 'عناوين ثابتة قد تكون خوادم تحكم أو خدمات قديمة، وتصعّب الصيانة.', 'استخدم أسماء نطاقات وإعدادات خارجية، وراجع سبب وجود العنوان.', None, check=_is_public_ip),
]


def _is_comment_only(line, lang):
    s = line.strip()
    if not s:
        return True
    if lang in ('python', 'shell', 'powershell') and s.startswith('#') and not s.startswith('#!'):
        return True
    if lang in ('javascript', 'java', 'c', 'csharp', 'php', 'general', 'html'):
        if s.startswith(('//', '/*', '*', '<!--')) or (lang in ('php', 'general') and s.startswith('#')):
            return True
    if lang == 'sql' and s.startswith('--'):
        return True
    return False


def _mask_snippet(snippet):
    def sub(m):
        v = m.group(0)
        return v[:4] + '•' * min(max(len(v) - 4, 3), 8)
    out = re.sub(r'["\']([^"\'\s]{6,})["\']', lambda m: '"' + m.group(1)[:3] + '•••"', snippet)
    out = re.sub(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bsk_live_[0-9a-zA-Z]{16,}\b|\beyJ[A-Za-z0-9_.-]{20,}', sub, out)
    out = re.sub(r'(://[^/\s:@]+:)[^@\s]+(@)', r'\1•••\2', out)
    return out


def analyze_code(code, language='auto'):
    code = (code or '').replace('\r\n', '\n').replace('\r', '\n')
    if not code.strip():
        raise ValueError('الصق كوداً لتحليله أولاً.')
    if len(code) > 200_000:
        raise ValueError('الكود كبير جداً. الحد الأقصى 200 ألف حرف.')
    lang = language if language in LANG_LABELS else 'auto'
    detected = detect_language(code) if lang == 'auto' else lang
    active = LANG_GROUPS.get(detected, {detected})
    lines = code.split('\n')

    hits = {}  # rule id -> {rule, lines: [(n, snippet)], count}
    seen_group_lines = set()
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line[:2000]
        comment = _is_comment_only(line, detected)
        for rule in RULES:
            if rule['langs'] is not None and 'general' not in rule['langs'] and not (rule['langs'] & active):
                continue
            if comment and not rule['allow_comment']:
                continue
            key = (rule['group'], idx)
            if key in seen_group_lines:
                continue
            m = rule['re'].search(line)
            if not m:
                continue
            if rule['check'] and not rule['check'](line, m):
                continue
            seen_group_lines.add(key)
            snippet = line.strip()
            if len(snippet) > 160:
                snippet = snippet[:157] + '…'
            if rule['mask']:
                snippet = _mask_snippet(snippet)
            h = hits.setdefault(rule['id'], {'rule': rule, 'lines': [], 'count': 0})
            h['count'] += 1
            if len(h['lines']) < 5:
                h['lines'].append({'line': idx, 'snippet': snippet})

    findings = []
    for h in hits.values():
        r = h['rule']
        findings.append({
            'id': r['id'], 'title': r['title'], 'severity': r['severity'], 'desc': r['desc'], 'fix': r['fix'],
            'cwe': r['cwe'], 'count': h['count'], 'locations': h['lines'],
        })

    # مؤشرات عامة على مستوى الملف
    long_lines = [i for i, l in enumerate(lines, 1) if len(l) > 600]
    if long_lines and len(lines) < 40:
        findings.append({'id': 'obf-minified', 'title': 'أسطر طويلة جداً (كود مضغوط أو مُعتّم)', 'severity': 'low',
                         'desc': 'قد يكون الكود مضغوطاً (Minified) أو متعمّد الإخفاء، ما يصعّب مراجعته.',
                         'fix': 'اطلب النسخة المصدرية الأصلية أو افحص الكود بعد تنسيقه.', 'cwe': 'CWE-506',
                         'count': len(long_lines), 'locations': [{'line': long_lines[0], 'snippet': f'سطر بطول {len(lines[long_lines[0]-1])} حرفاً'}]})

    findings.sort(key=lambda f: (SEV_ORDER.get(f['severity'], 9), -f['count']))

    # الدرجة: وزن لكل قاعدة + زيادة صغيرة للتكرار
    score = 0
    for f in findings:
        w = SEV_WEIGHT_CODE.get(f['severity'], 0)
        score += w + min(f['count'] - 1, 3) * (w // 4)
    score = min(100, score)
    if any(f['severity'] == 'high' for f in findings):
        level = 'high' if score >= 40 or sum(1 for f in findings if f['severity'] == 'high') >= 2 else 'medium'
    elif score >= 20:
        level = 'medium'
    elif score > 0:
        level = 'low'
    else:
        level = 'none'

    # الروابط داخل الكود
    ignore = ('w3.org', 'xmlns', 'schemas.', 'localhost', '127.0.0.1', 'example.com', 'example.org', 'apache.org/licenses', 'json-schema.org', 'mozilla.org/MPL', 'opensource.org')
    urls, seen = [], set()
    for u in URL_IN_TEXT_RE.findall(code):
        u = u.rstrip('.,;:')
        if u in seen or any(i in u for i in ignore):
            continue
        seen.add(u)
        loc = analyze_url_local(u)
        urls.append({'url': u[:300], 'risk': loc['risk'], 'issues': [f['title'] for f in loc['findings'] if f['severity'] != 'info'][:3]})
        if len(urls) >= 15:
            break

    counts = {s: sum(1 for f in findings if f['severity'] == s) for s in ('high', 'medium', 'low')}
    return {
        'language': detected, 'language_label': LANG_LABELS.get(detected, detected), 'auto_detected': lang == 'auto',
        'lines': len(lines), 'chars': len(code), 'score': score, 'risk': level, 'counts': counts,
        'findings': findings, 'urls': urls,
    }
