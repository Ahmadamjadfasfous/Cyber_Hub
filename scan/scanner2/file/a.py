from scanner.file_scanner import scan_file
from scanner.url_scanner import scan_url
import os
import zipfile
import shutil
import logging
import math
from flask import Flask, request, jsonify, render_template
import yara

# إعداد تطبيق Flask
app = Flask(__name__)

# إعداد السجلات (Logs) للمراقبة
logging.basicConfig(level=logging.INFO)

# إعداد مسارات القواعد والمجلدات المؤقتة
RULES_DIR = r"C:\\Users\\NITRO 5\\Desktop\\scanner2\\file\\rules"
UPLOAD_DIR = "uploads/"
EXTRACT_DIR = os.path.join(UPLOAD_DIR, "extracted")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# قائمة الاستثناءات (Whitelist)
WHITELIST = ["LeagueOfLegends.exe", "SomeTrustedApp.exe"]

# تحميل قواعد Yara
def load_yara_rules(rules_dir):
    try:
        if not os.path.exists(rules_dir):
            logging.error(f"Rules directory does not exist: {rules_dir}")
            return None
        rules = yara.compile(filepaths={
            f: os.path.join(rules_dir, f) 
            for f in os.listdir(rules_dir) if f.endswith('.yar')
        })
        logging.info(f"Yara rules loaded successfully from {rules_dir}")
        return rules
    except yara.SyntaxError as e:
        logging.error(f"Syntax error in Yara rules: {e}")
        return None
    except PermissionError as e:
        logging.error(f"Permission denied: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error while loading rules: {e}")
        return None

# حساب الانتروبيا (Entropy) لتحليل الملفات
def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        entropy = -sum(
            (data.count(byte) / len(data)) * math.log2(data.count(byte) / len(data))
            for byte in set(data)
        )
        return entropy
    except Exception as e:
        logging.error(f"Error calculating entropy: {e}")
        return 0

# فحص الملفات باستخدام Yara وقائمة الاستثناءات وتحليل الانتروبيا
def enhanced_scan_file(file_path, rules):
    try:
        # التحقق من قائمة الاستثناءات
        if os.path.basename(file_path) in WHITELIST:
            logging.info(f"File {file_path} is whitelisted. Skipping scan.")
            return None

        # حساب الانتروبيا
        entropy = calculate_entropy(file_path)
        logging.info(f"File {file_path} entropy: {entropy:.2f}")
        if 7.5 <= entropy <= 8.0:
            logging.warning(f"File {file_path} has high entropy. Possible packed or encrypted file.")

        # فحص باستخدام Yara
        matches = scan_file(file_path, rules)
        return matches
    except Exception as e:
        logging.error(f"Error during file scan: {e}")
        return None

# تحميل قواعد Yara عند بدء التشغيل
rules = load_yara_rules(RULES_DIR)
if not rules:
    logging.error("Failed to load Yara rules. Exiting application.")
    exit(1)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan/file', methods=['POST'])
def scan_file_endpoint():
    if 'file' not in request.files:
        logging.warning("No file provided in the request.")
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        # حفظ الملف المرفوع
        file.save(file_path)
        logging.info(f"File saved for scanning: {file_path}")

        # تحقق إذا كان الملف مضغوطًا
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                os.makedirs(EXTRACT_DIR, exist_ok=True)
                zip_ref.extractall(EXTRACT_DIR)
                logging.info(f"Extracted ZIP file to: {EXTRACT_DIR}")

            results = []
            for root, dirs, files in os.walk(EXTRACT_DIR):
                for extracted_file in files:
                    extracted_file_path = os.path.join(root, extracted_file)
                    result = enhanced_scan_file(extracted_file_path, rules)
                    if result:
                        results.append({"file": extracted_file, "matches": [str(match) for match in result]})

            shutil.rmtree(EXTRACT_DIR)
            os.remove(file_path)

            if results:
                return jsonify({"status": "Malicious", "details": results}), 200
            else:
                return jsonify({"status": "Clean"}), 200
        else:
            # فحص الملف إذا لم يكن مضغوطًا
            result = enhanced_scan_file(file_path, rules)
            os.remove(file_path)
            if result:
                return jsonify({"status": "Malicious", "details": [str(match) for match in result]}), 200
            else:
                return jsonify({"status": "Clean"}), 200
    except Exception as e:
        logging.error(f"Error while scanning file: {e}")
        return jsonify({"error": f"Unexpected error: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
