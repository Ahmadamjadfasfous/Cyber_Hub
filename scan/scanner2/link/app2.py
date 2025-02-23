from flask import Flask, render_template, request, jsonify
import validators
import whois
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse
import os
import tarfile

app = Flask(__name__)

# تحميل بيانات البلاكليست والوايتليست (هذه مجرد أمثلة)
BLACKLIST_DIR = 'blacklist'
WHITELIST_DIR = 'whitelist'

# وظيفة التحقق من الرابط
def validate_url(url):
    if not validators.url(url):
        return False
    return True

# وظيفة توحيد الرابط
def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return url

# وظيفة للحصول على معلومات النطاق (WHOIS)
def get_domain_info(url):
    try:
        domain = whois.whois(urlparse(url).netloc)
        return {
            "domain_name": domain.domain_name if domain.domain_name else 'غير متوفر',
            "registrar": domain.registrar if domain.registrar else 'غير متوفر',
            "creation_date": domain.creation_date if domain.creation_date else 'غير متوفر',
            "expiration_date": domain.expiration_date if domain.expiration_date else 'غير متوفر',
        }
    except Exception as e:
        return {"error": "خطأ غير متوقع أثناء استرجاع معلومات WHOIS: " + str(e)}

# وظيفة لتحليل شهادة SSL
def get_ssl_info(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer", 'غير متوفر'),
                    "valid_from": cert.get("notBefore", 'غير متوفر'),
                    "valid_to": cert.get("notAfter", 'غير متوفر'),
                }
    except ssl.SSLError as e:
        return {"error": "فشل في استرجاع شهادة SSL: " + str(e)}
    except Exception as e:
        return {"error": "خطأ غير متوقع أثناء استرجاع شهادة SSL: " + str(e)}

# وظيفة لتحليل سجلات DNS
def get_dns_info(url):
    try:
        domain = urlparse(url).netloc
        dns_info = {}

        # استخراج سجل A (عنوان IP)
        dns_info["A Record"] = [str(ip.address) for ip in dns.resolver.resolve(domain, 'A')] if dns.resolver.resolve(domain, 'A') else ['غير متوفر']
        
        # استخراج سجلات MX (خوادم البريد)
        dns_info["MX Record"] = [mx.exchange.to_text() for mx in dns.resolver.resolve(domain, 'MX')] if dns.resolver.resolve(domain, 'MX') else ['غير متوفر']

        # استخراج سجلات NS (خوادم الأسماء)
        dns_info["NS Record"] = [ns.target.to_text() for ns in dns.resolver.resolve(domain, 'NS')] if dns.resolver.resolve(domain, 'NS') else ['غير متوفر']

        return dns_info
    except dns.resolver.NoAnswer as e:
        return {"error": "فشل في استرجاع سجلات DNS: " + str(e)}
    except Exception as e:
        return {"error": "خطأ غير متوقع أثناء استرجاع سجلات DNS: " + str(e)}

# وظيفة لتحليل الملفات في المجلدات (البلاك ليست / الوايت ليست)
def load_blacklist_and_whitelist():
    blacklisted_urls = set()
    whitelisted_urls = set()

    # تحميل البلاك ليست
    for filename in os.listdir(BLACKLIST_DIR):
        file_path = os.path.join(BLACKLIST_DIR, filename)
        if file_path.endswith(('.txt', '.tar', '.tar.gz')):
            try:
                if file_path.endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        blacklisted_urls.update([line.strip() for line in f])
                elif file_path.endswith('.tar') or file_path.endswith('.tar.gz'):
                    with open(file_path, 'rb') as f:
                        with tarfile.open(fileobj=f) as tar:
                            for member in tar.getmembers():
                                if member.isfile() and member.name.endswith('.txt'):
                                    file_content = tar.extractfile(member).read().decode('utf-8', errors='ignore')
                                    blacklisted_urls.update(file_content.splitlines())
            except UnicodeDecodeError as e:
                print(f"Unicode decode error in blacklist file {file_path}: {e}")
            except Exception as e:
                print(f"Error reading blacklist file {file_path}: {e}")

    # تحميل الوايت ليست
    for filename in os.listdir(WHITELIST_DIR):
        file_path = os.path.join(WHITELIST_DIR, filename)
        if file_path.endswith(('.txt', '.tar', '.tar.gz')):
            try:
                if file_path.endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        whitelisted_urls.update([line.strip() for line in f])
                elif file_path.endswith('.tar') or file_path.endswith('.tar.gz'):
                    with open(file_path, 'rb') as f:
                        with tarfile.open(fileobj=f) as tar:
                            for member in tar.getmembers():
                                if member.isfile() and member.name.endswith('.txt'):
                                    file_content = tar.extractfile(member).read().decode('utf-8', errors='ignore')
                                    whitelisted_urls.update(file_content.splitlines())
            except UnicodeDecodeError as e:
                print(f"Unicode decode error in whitelist file {file_path}: {e}")
            except Exception as e:
                print(f"Error reading whitelist file {file_path}: {e}")

    return blacklisted_urls, whitelisted_urls


# فحص الروابط
def scan_url(url):
    blacklisted_urls, whitelisted_urls = load_blacklist_and_whitelist()
    url = normalize_url(url)

    if not validate_url(url):
        return {"status": "Error", "reason": "رابط غير صالح", "color": "red"}

    result = {
        "status": "Clean",
        "reason": "Not in lists",
        "color": "green",  # اللون الأخضر إذا كان الرابط نظيفًا
        "domain_info": get_domain_info(url),
        "ssl_info": get_ssl_info(url),
        "dns_info": get_dns_info(url),
    }

    # طباعة نتائج الفحص لكل جزء
    print("WHOIS Info:", result['domain_info'])
    print("SSL Info:", result['ssl_info'])
    print("DNS Info:", result['dns_info'])

    if url in whitelisted_urls:
        result["status"] = "Clean"
        result["reason"] = "Whitelisted"
        result["color"] = "green"  # اللون الأخضر إذا كان في الوايت ليست
    elif url in blacklisted_urls:
        result["status"] = "Malicious"
        result["reason"] = "Blacklisted"
        result["color"] = "red"  # اللون الأحمر إذا كان في البلاك ليست

    return result

# نقطة النهاية لعرض الصفحة الرئيسية (index.html)
@app.route('/')
def index():
    return render_template('index.html')

# نقطة النهاية لفحص الروابط
@app.route('/scan/url', methods=['POST'])
def scan_url_endpoint():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "لم يتم توفير الرابط"}), 400

    url = data['url']
    result = scan_url(url)
    return jsonify(result), 200

if __name__ == '__main__':
    print("Server running at http://127.0.0.1:5001")
    app.run(port=5001, debug=True)
