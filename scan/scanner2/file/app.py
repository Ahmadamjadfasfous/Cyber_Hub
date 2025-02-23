from scanner.file_scanner import scan_file
import os
import zipfile
import shutil
import logging
import json
from flask import Flask, request, jsonify, render_template
import yara

# إعداد تطبيق Flask
app = Flask(__name__)

# إعداد السجلات (Logs) للمراقبة
logging.basicConfig(level=logging.INFO)

# إعداد مسارات القواعد والمجلدات المؤقتة
RULES_DIR = r"C:\\Users\\NITRO 5\\Desktop\\scanner2\\file\\rules"
THREAT_DB_DIR = r"C:\\Users\\NITRO 5\\Desktop\\scanner2\\file\\threat_db"
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
        rules_files = {
            f"rule_{idx}": os.path.join(rules_dir, f)
            for idx, f in enumerate(os.listdir(rules_dir)) if f.endswith('.yar')
        }
        rules = yara.compile(filepaths=rules_files)
        logging.info(f"Yara rules loaded successfully from {rules_dir}")
        return rules
    except Exception as e:
        logging.error(f"Error loading Yara rules: {e}")
        return None

# تحميل قواعد JSON
def load_threat_db(db_dir):
    threat_data = []
    try:
        if not os.path.exists(db_dir):
            logging.error(f"Threat database directory does not exist: {db_dir}")
            return []
        for file_name in os.listdir(db_dir):
            if file_name.endswith(".json"):
                with open(os.path.join(db_dir, file_name), 'r') as f:
                    data = json.load(f)
                    threat_data.append(data)
        logging.info(f"Threat database loaded successfully from {db_dir}")
    except Exception as e:
        logging.error(f"Error loading threat database: {e}")
    return threat_data

# مقارنة بصمة TLSH
def compare_tlsh(file_tlsh, threat_db):
    for threat in threat_db:
        if threat.get("tlsh") == file_tlsh:
            return threat
    return None

# حساب بصمة TLSH للملف (محاكية فقط)
def calculate_tlsh(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        # محاكاة حساب TLSH
        return str(hash(data))
    except Exception as e:
        logging.error(f"Error calculating TLSH: {e}")
        return None

# البحث عبر الإنترنت عن معلومات التهديد
def search_threat_online(threat_name):
    try:
        search_url = f"https://www.google.com/search?q={threat_name.replace(' ', '+')}"
        return search_url
    except Exception as e:
        logging.error(f"Error during online threat search: {e}")
        return None

# فحص الملفات باستخدام Yara وقائمة الاستثناءات وتحليل بصمة TLSH
def enhanced_scan_file(file_path, rules, threat_db):
    try:
        # التحقق من قائمة الاستثناءات
        if os.path.basename(file_path) in WHITELIST:
            logging.info(f"File {file_path} is whitelisted. Skipping scan.")
            return None

        # حساب بصمة TLSH
        file_tlsh = calculate_tlsh(file_path)
        matched_threat = compare_tlsh(file_tlsh, threat_db)
        if matched_threat:
            threat_name = matched_threat.get("name", "Unknown Threat")
            online_info = search_threat_online(threat_name)
            return {
                "type": "Signature",
                "details": matched_threat,
                "recommendation": "Delete the file immediately and consult a security expert.",
                "online_info": online_info
            }

        # فحص باستخدام Yara
        matches = scan_file(file_path, rules)
        if matches:
            threat_name = matches[0].rule if matches else "Unknown Threat"
            online_info = search_threat_online(threat_name)
            return {
                "type": "Yara",
                "details": [str(match) for match in matches],
                "recommendation": "Inspect the file manually or consult a security expert.",
                "online_info": online_info
            }

        return None
    except Exception as e:
        logging.error(f"Error during file scan: {e}")
        return None

# تحميل قواعد Yara وقواعد JSON عند بدء التشغيل
rules = load_yara_rules(RULES_DIR)
if not rules:
    logging.error("Failed to load Yara rules. Exiting application.")
    exit(1)

threat_db = load_threat_db(THREAT_DB_DIR)

@app.route('/')
def index():
    try:
        return render_template("index.html")
    except Exception as e:
        logging.error(f"Error loading index.html: {e}")
        return "Welcome to the Malware Scanner! The index page is missing.", 404

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

        # جمع معلومات الملف (حجم ونوع)
        file_info = {
            "name": file.filename,
            "size": os.path.getsize(file_path),
            "type": file.content_type,
        }

        # تحقق إذا كان الملف مضغوطًا
        if zipfile.is_zipfile(file_path):
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.testzip()  # يختبر ما إذا كانت الملفات داخل الأرشيف سليمة
                    os.makedirs(EXTRACT_DIR, exist_ok=True)
                    zip_ref.extractall(EXTRACT_DIR)
                    logging.info(f"Extracted ZIP file to: {EXTRACT_DIR}")
            except zipfile.BadZipFile:
                logging.error("Invalid ZIP file or extraction error.")
                return jsonify({"error": "Failed to extract the ZIP file."}), 400
            except Exception as e:
                logging.error(f"Unexpected error while extracting ZIP: {e}")
                return jsonify({"error": "Error occurred while extracting ZIP file."}), 500

            results = []
            for root, dirs, files in os.walk(EXTRACT_DIR):
                for extracted_file in files:
                    extracted_file_path = os.path.join(root, extracted_file)
                    try:
                        result = enhanced_scan_file(extracted_file_path, rules, threat_db)
                        if result:
                            results.append({
                                "file": extracted_file,
                                "result": result
                            })
                    except Exception as e:
                        logging.error(f"Error during scan of {extracted_file}: {e}")

            shutil.rmtree(EXTRACT_DIR, ignore_errors=True)
            os.remove(file_path)

            if results:
                return jsonify({
                    "status": "Malicious",
                    "details": results,
                    "file_info": file_info,
                    "recommendation": "Delete malicious files and consult with a security expert.",
                }), 200
            else:
                return jsonify({"status": "Clean", "file_info": file_info}), 200
        else:
            # فحص الملف إذا لم يكن مضغوطًا
            result = enhanced_scan_file(file_path, rules, threat_db)
            os.remove(file_path)
            if result:
                return jsonify({
                    "status": "Malicious",
                    "details": result,
                    "file_info": file_info,
                    "recommendation": "Delete the file immediately and consult a security expert.",
                }), 200
            else:
                return jsonify({"status": "Clean", "file_info": file_info}), 200
    except Exception as e:
        logging.error(f"Error while scanning file: {e}")
        return jsonify({"error": f"Unexpected error: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
