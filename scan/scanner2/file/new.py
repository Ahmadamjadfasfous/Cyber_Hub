import os
import yara
import hashlib
import zipfile
from flask import Flask, render_template, request

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')


# Compile the Yara rules
rules = yara.compile(filepath='rules.yar')

def scan_file_with_yara(file_path):
    try:
        matches = rules.match(file_path)
        if matches:
            return f"Yara detected: {', '.join([match.rule for match in matches])}"
        else:
            return "No Yara match detected"
    except Exception as e:
        return f"Error scanning file with Yara: {e}"

# Example: Integrating with your existing scan function
def scan_file(file_path, signatures):
    # Existing hash-based scanning logic here...
    
    # Add Yara scanning
    yara_result = scan_file_with_yara(file_path)
    if "detected" in yara_result:
        return yara_result
    
    # If no Yara detection, continue with hash-based logic
    return "File is clean"
# وظيفة لتحليل ملفات التواقيع من ملفات hdb
def parse_signatures_from_hdb(signature_file):
    signatures = []
    with open(signature_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 3:  # يجب أن يحتوي السطر على ثلاثة أجزاء: hash:size:virus_name
                signature_hash = parts[0]
                virus_name = parts[2]
                signatures.append((signature_hash, virus_name))
    return signatures

# تحميل وتحليل جميع ملفات التواقيع
def load_all_signatures(directory):
    all_signatures = []
    for file_name in os.listdir(directory):
        if file_name.endswith('.hdb'):  # التركيز على ملفات .hdb
            file_path = os.path.join(directory, file_name)
            all_signatures.extend(parse_signatures_from_hdb(file_path))
    return all_signatures

# تحميل التواقيع من الملفات المستخرجة في نفس المسار الذي يحتوي على app.py
signatures = load_all_signatures(os.path.join(os.getcwd(), 'main_extracted'))  # ضع مسار ملفات التواقيع هنا

# وظيفة لحساب MD5 للملف
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# وظيفة لفحص الملفات المضغوطة (ZIP)
def scan_zip_file(zip_path, signatures):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            with zip_ref.open(file_info) as extracted_file:
                file_data = extracted_file.read()
                file_md5 = hashlib.md5(file_data).hexdigest()

                for signature_hash, virus_name in signatures:
                    if file_md5 == signature_hash:
                        return f"تم اكتشاف فيروس: {virus_name} في {file_info.filename}"
    return "الملف نظيف"

# وظيفة لفحص الملفات (بدون التحقق من الحجم)
def scan_file(file_path, signatures):
    if zipfile.is_zipfile(file_path):
        return scan_zip_file(file_path, signatures)

    file_md5 = calculate_md5(file_path)  # حساب MD5 للملف
    for signature_hash, virus_name in signatures:
        if file_md5 == signature_hash:
            return f"تم اكتشاف فيروس: {virus_name}"
    return "الملف نظيف"

# إنشاء الواجهة باستخدام Flask
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            return "لا يوجد ملف مرفوع"
        file = request.files['file']
        if file.filename == '':
            return "اسم الملف فارغ"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        result = scan_file(file_path, signatures)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
