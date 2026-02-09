from flask import Flask, request, jsonify
import requests
from user_agent import generate_user_agent
import os  # ضروري لجلب رقم المنفذ من السيرفر العالمي

app = Flask(__name__)

@app.route('/send', methods=['POST', 'GET'])
def send_likes():
    # استقبال الرابط سواء من طلب POST (JSON) أو GET (Query Params)
    if request.method == 'POST':
        data_json = request.get_json()
        url = data_json.get('url') if data_json else None
    else:
        url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL is missing"}), 400

    # --- بداية المنطق الخاص بك بالكامل دون أي تعديل ---
    
    re = requests.get('https://leofame.com/ar/free-tiktok-likes')
    ses = re.cookies.get_dict()
    
    token = ses.get('token', '')
    ci_session = ses.get('ci_session', '')

    cookies = {
        'token': token,
        'ci_session': ci_session,
        'cfz_google-analytics_v4': '%7B%22mHFS_engagementDuration%22%3A%7B%22v%22%3A%220%22%2C%22e%22%3A1802191052997%7D%2C%22mHFS_engagementStart%22%3A%7B%22v%22%3A1770655057824%2C%22e%22%3A1802191058757%7D%2C%22mHFS_counter%22%3A%7B%22v%22%3A%229%22%2C%22e%22%3A1802191052997%7D%2C%22mHFS_ga4sid%22%3A%7B%22v%22%3A%22174289570%22%2C%22e%22%3A1770656852997%7D%2C%22mHFS_session_counter%22%3A%7B%22v%22%3A%221%22%2C%22e%22%3A1802191052997%7D%2C%22mHFS_ga4%22%3A%7B%22v%22%3A%222f05b1b0-1dfc-43cd-9b12-09c17bef86d4%22%2C%22e%22%3A1802191052997%7D%2C%22mHFS_let%22%3A%7B%22v%22%3A%221770655052997%22%2C%22e%22%3A1802191052997%7D%7D',
    }

    headers = {
        'authority': 'leofame.com',
        'accept': '*/*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://leofame.com',
        'referer': 'https://leofame.com/ar/free-tiktok-likes',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': str(generate_user_agent()),
    }

    params = {
        'api': '1',
    }

    data = {
        'token': token,
        'timezone_offset': 'Asia/Baghdad',
        'free_link': url,
    }

    try:
        response = requests.post(
            'https://leofame.com/ar/free-tiktok-likes', 
            params=params, 
            cookies=cookies, 
            headers=headers, 
            data=data,
            timeout=20 # حماية للسيرفر من التعليق
        )
        
        # --- نهاية المنطق الخاص بك ---

        if "success" in response.text:
            return jsonify({
                "status": "success",
                "message": f"DONE : {url}"
            })
        else:
            return jsonify({
                "status": "failed",
                "message": f"حاول بعد 24 ساعه : {url}"
            })
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # هذه السطور هي ما تجعل الـ API "عالمي" ليقبل المنفذ من الاستضافة
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
