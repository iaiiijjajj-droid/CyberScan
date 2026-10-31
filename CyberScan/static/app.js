const form = document.getElementById('scan-form');
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const resultBox = document.getElementById('result');
const historyBox = document.getElementById('history');
const qrFile = document.getElementById('qr-file');
const qrReaderEl = document.getElementById('qr-reader');
const qrStatus = document.getElementById('qr-status');
const qrFound = document.getElementById('qr-found');
const qrUrl = document.getElementById('qr-url');
let qrScanner = null;

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function badgeClass(v) { return v === 'خبيث' ? 'bad' : v === 'مشبوه' ? 'warn' : v === 'لم تُكتشف تهديدات' ? 'good' : 'neutral'; }
function showError(message) { resultBox.classList.remove('hidden'); resultBox.innerHTML = `<div class="result-top"><h3>تعذر إكمال الفحص</h3><span class="badge warn">تنبيه</span></div><p class="result-note">${esc(message)}</p>`; }

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;
  scanBtn.disabled = true; scanBtn.querySelector('span').textContent = 'جاري الفحص…';
  resultBox.classList.remove('hidden');
  resultBox.innerHTML = '<div class="empty">نتصل بـ VirusTotal وننتظر نتيجة الفحص…</div>';
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url})});
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || 'حدث خطأ غير معروف.');
    if (data.pending) {
      resultBox.innerHTML = `<div class="result-top"><h3>الفحص قيد المعالجة</h3><span class="badge neutral">قيد الانتظار</span></div><p class="result-note">${esc(data.message)}</p><p class="result-url">${esc(data.url)}</p>`;
      return;
    }
    const cls = badgeClass(data.verdict);
    resultBox.innerHTML = `<div class="result-top"><h3>نتيجة الفحص</h3><span class="badge ${cls}">${esc(data.verdict)}</span></div>
      <div class="result-url">${esc(data.url)}</div>
      <div class="stats"><div class="stat bad"><strong>${data.malicious}</strong><span>محركات اعتبرته خبيثاً</span></div><div class="stat warn"><strong>${data.suspicious}</strong><span>محركات اعتبرته مشبوهاً</span></div><div class="stat good"><strong>${data.harmless}</strong><span>محركات لم تجده ضاراً</span></div><div class="stat"><strong>${data.undetected}</strong><span>لم تحدد نتيجة</span></div></div>
      <p class="result-note">المصدر: VirusTotal · مقياس المخاطر التقريبي: ${data.score}/100. هذه نتيجة المحركات المتاحة وليست ضماناً للسلامة.</p>`;
    loadHistory();
  } catch (err) { showError(err.message || 'تعذر الاتصال بالخادم.'); }
  finally { scanBtn.disabled = false; scanBtn.querySelector('span').textContent = 'افحص الرابط'; }
});

async function loadHistory() {
  try {
    const res = await fetch('/api/history'); const rows = await res.json();
    if (!rows.length) { historyBox.innerHTML = '<div class="empty">ماكو فحوصات محفوظة لحد الآن.</div>'; return; }
    historyBox.innerHTML = rows.map(r => `<div class="history-item"><div class="history-url">${esc(r.url)}</div><div class="history-meta"><span class="badge ${badgeClass(r.verdict)}">${esc(r.verdict)}</span><span class="score">${r.score}/100</span></div></div>`).join('');
  } catch { historyBox.innerHTML = '<div class="empty">تعذر تحميل سجل الفحوصات.</div>'; }
}
document.getElementById('refresh-history').addEventListener('click', loadHistory);
document.getElementById('scan-qr-url').addEventListener('click', () => { urlInput.value = qrUrl.value; form.requestSubmit(); window.scrollTo({top:0,behavior:'smooth'}); });
function setQrStatus(msg, isError=false) { qrStatus.textContent = msg; qrStatus.classList.remove('hidden'); qrStatus.style.color = isError ? 'var(--red)' : 'var(--yellow)'; }
function acceptQrText(text) {
  const value = (text || '').trim();
  if (!value) { setQrStatus('ما قدرنا نستخرج نص من الرمز.', true); return; }
  qrUrl.value = value; qrFound.classList.remove('hidden');
  if (/^https?:\/\//i.test(value) || /^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(value)) {
    setQrStatus('تم استخراج رابط من QR. افحصه قبل فتحه.');
  } else { setQrStatus('تم استخراج النص، لكنه لا يبدو رابط ويب. تحقق منه قبل استخدامه.', true); }
}

document.getElementById('camera-btn').addEventListener('click', async () => {
  if (!window.isSecureContext && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
    setQrStatus('المتصفح يمنع الكاميرا لأن الموقع مفتوح عبر HTTP من عنوان الحاسبة. جرّب رفع الموقع إلى استضافة HTTPS، أو استخدم رفع صورة QR حالياً.', true);
    return;
  }
  if (typeof Html5Qrcode === 'undefined') { setQrStatus('تعذر تحميل مكتبة QR. تأكد من الإنترنت ثم حدّث الصفحة.', true); return; }
  qrReaderEl.classList.remove('hidden');
  document.getElementById('stop-camera').classList.remove('hidden');
  document.getElementById('camera-btn').disabled = true;
  try {
    qrScanner = new Html5Qrcode('qr-reader');
    const cameras = await Html5Qrcode.getCameras();
    if (!cameras.length) throw new Error('لم يتم العثور على كاميرا متاحة.');
    const cam = cameras.find(c => /back|rear|environment/i.test(c.label)) || cameras[0];
    await qrScanner.start(cam.id, {fps:10, qrbox:{width:230,height:230}}, async decoded => {
      acceptQrText(decoded);
      try { await qrScanner.stop(); await qrScanner.clear(); } catch {}
      qrScanner = null; qrReaderEl.classList.add('hidden');
      document.getElementById('stop-camera').classList.add('hidden'); document.getElementById('camera-btn').disabled = false;
    }, () => {});
    setQrStatus('وجّه الكاميرا نحو رمز QR. اسمح للمتصفح باستخدام الكاميرا إذا طلب ذلك.');
  } catch (e) {
    let reason = e && e.message ? e.message : String(e || 'خطأ غير معروف');
    if (/permission|denied|notallowed/i.test(reason)) reason = 'لم يحصل المتصفح على إذن الكاميرا. اسمح للكاميرا من إعدادات الموقع.';
    setQrStatus('تعذر تشغيل الكاميرا: ' + reason + '. الكاميرا تحتاج HTTPS أو localhost.', true);
    document.getElementById('camera-btn').disabled = false;
    document.getElementById('stop-camera').classList.add('hidden');
    if (qrScanner) { try { await qrScanner.clear(); } catch {} qrScanner = null; }
  }
});
document.getElementById('stop-camera').addEventListener('click', async () => {
  if (qrScanner) { try { await qrScanner.stop(); await qrScanner.clear(); } catch {} qrScanner = null; }
  qrReaderEl.classList.add('hidden'); document.getElementById('stop-camera').classList.add('hidden'); document.getElementById('camera-btn').disabled = false; setQrStatus('تم إيقاف الكاميرا.');
});
qrFile.addEventListener('change', async () => {
  const file = qrFile.files && qrFile.files[0]; if (!file) return;
  qrReaderEl.classList.remove('hidden'); qrReaderEl.innerHTML = '';
  setQrStatus('جاري محاولة قراءة رمز QR من الصورة…');
  try {
    let decodedText = '';
    // Primary image decoder: jsQR. It reads the selected image locally in the browser.
    if (typeof jsQR !== 'undefined' && window.createImageBitmap) {
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d', {willReadFrequently: true});
      // Keep the original resolution for small QR codes; cap huge images to avoid excessive memory use.
      const scale = Math.min(1, 1800 / Math.max(bitmap.width, bitmap.height));
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, {inversionAttempts: 'attemptBoth'});
      if (code && code.data) decodedText = code.data;
      if (bitmap.close) bitmap.close();
    }
    // Fallback decoder for browsers where jsQR cannot read the image.
    if (!decodedText && typeof Html5Qrcode !== 'undefined') {
      const scanner = new Html5Qrcode('qr-reader');
      try { decodedText = await scanner.scanFile(file, true); }
      finally { try { await scanner.clear(); } catch {} }
    }
    if (!decodedText) throw new Error('لم يتم العثور على QR قابل للقراءة داخل الصورة. تأكد أن الصورة تحتوي رمز QR واضحاً وكاملاً، وليس باركوداً خطياً.');
    acceptQrText(decodedText);
  } catch (e) {
    setQrStatus((e && e.message && e.message.includes('لم يتم العثور')) ? e.message : 'فشلت قراءة الصورة. جرّب صورة PNG أو JPG أوضح، واجعل رمز QR كاملاً وغير مقصوص. إذا كانت مكتبات القراءة لم تُحمّل، تأكد من اتصال الإنترنت ثم حدّث الصفحة.', true);
  } finally {
    qrReaderEl.classList.add('hidden');
    qrFile.value = '';
  }
});
loadHistory();
