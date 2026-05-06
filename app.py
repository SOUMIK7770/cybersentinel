import streamlit as st
import requests
import time
import os
import re
import base64
import html
from dotenv import load_dotenv

# =====================
# ENV
# =====================
load_dotenv(override=True)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", os.getenv("VT_API_KEY", "")).strip(' \t\n\r"')
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip(' \t\n\r"')

# =====================
# STATE
# =====================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "cache" not in st.session_state:
    st.session_state.cache = {}

if "mode" not in st.session_state:
    st.session_state.mode = "URL"

# =====================
# PAGE CONFIG
# =====================
st.set_page_config(page_title="CyberSentinel AI", layout="wide", page_icon="🛡️")

# =====================
# CSS (PREMIUM CYBER UI)
# =====================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

body, .stApp {
    font-family: 'Inter', sans-serif;
    background: #090e17; 
    color: #f1f5f9;
}

/* TITLE */
.title {
    text-align: center;
    margin-top: 30px;
    margin-bottom: 40px;
}

.title h1 {
    font-size: 52px;
    font-weight: 800;
    letter-spacing: -1.5px;
    background: linear-gradient(135deg, #00f5ff 0%, #8b5cf6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 15px;
}

.title p {
    color: #94a3b8;
    font-size: 18px;
    font-weight: 400;
    max-width: 600px;
    margin: 0 auto;
    line-height: 1.6;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}

div.stButton > button {
    width: 100%;
    border-radius: 10px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #f8fafc;
    padding: 12px 15px;
    font-weight: 600;
    font-size: 15px;
    transition: all 0.2s ease;
    text-align: left;
    display: flex;
    justify-content: flex-start;
}

div.stButton > button:hover {
    border-color: #8b5cf6;
    background: #2e1065;
    color: #ffffff;
    box-shadow: 0 0 15px rgba(139, 92, 246, 0.4);
    transform: translateY(-1px);
}

div.stButton > button:active {
    transform: translateY(0px);
}

/* CHAT */
.chat-container {
    max-width: 850px;
    margin: 0 auto;
    padding-bottom: 120px;
}

.chat-bubble {
    padding: 20px 24px;
    margin: 16px 0;
    font-size: 15px;
    line-height: 1.6;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    animation: fadeIn 0.3s ease-out;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.user-bubble {
    background: #1e293b;
    color: #e2e8f0;
    border-radius: 20px 20px 4px 20px;
    text-align: right;
    margin-left: auto;
    max-width: 75%;
    border: 1px solid #334155;
}

.ai-bubble {
    background: #111827;
    color: #e2e8f0;
    border-radius: 20px 20px 20px 4px;
    margin-right: auto;
    max-width: 85%;
    border: 1px solid #1e293b;
    position: relative;
    overflow: hidden;
}

/* SUBTLE GLOW FOR AI */
.ai-bubble::before {
    content: '';
    position: absolute;
    top: 0; left: 0; width: 4px; height: 100%;
    background: #8b5cf6;
}

/* BADGE */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 6px 14px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 1px;
    margin-bottom: 16px;
    text-transform: uppercase;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.badge-icon {
    margin-right: 6px;
    font-size: 14px;
}

.low {
    background: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.medium {
    background: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.high {
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

/* INPUT */
.stChatInput > div {
    background: #1e293b !important;
    border-radius: 16px;
    border: 1px solid #334155;
    padding: 4px;
}
.stChatInput > div:focus-within {
    border-color: #00f5ff;
    box-shadow: 0 0 0 1px #00f5ff, 0 0 20px rgba(0, 245, 255, 0.2);
}

/* LINKS */
a {
    color: #00f5ff;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}

</style>
""", unsafe_allow_html=True)

# =====================
# HELPERS
# =====================
def format_markdown(text):
    # Escape HTML to prevent injection but allow our custom formatting
    text = html.escape(text)
    # Bold
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color: #fff;">\1</strong>', text)
    # Italics
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    # Inline code
    text = re.sub(r'`(.*?)`', r'<code style="background:#1e293b; color:#00f5ff; padding:2px 6px; border-radius:4px; font-size:13px;">\1</code>', text)
    # Lists
    text = re.sub(r'^\s*-\s+(.*)', r'<div style="margin-left: 15px; margin-bottom: 4px;">&bull; \1</div>', text, flags=re.MULTILINE)
    # Headers
    text = re.sub(r'^###\s+(.*)', r'<h4 style="color:#00f5ff; margin-top:16px; margin-bottom:8px;">\1</h4>', text, flags=re.MULTILINE)
    # Paragraphs (newlines)
    text = text.replace('\n', '<br>')
    # Clean up double br around divs
    text = text.replace('<br><div', '<div')
    text = text.replace('</div><br>', '</div>')
    return text

# =====================
# GEMINI
# =====================
def call_gemini(prompt):
    if not GEMINI_API_KEY:
        return "⚠ GEMINI_API_KEY is not set. Please configure your environment variables."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    for delay in [1, 3, 5]:
        try:
            res = requests.post(url, json=payload, timeout=15)
            if res.status_code == 200:
                data = res.json()
                if "candidates" in data:
                    return data["candidates"][0]["content"]["parts"][0]["text"].strip()
                else:
                    print("⚠ Gemini format:", data)
            else:
                print(f"⚠ Gemini API error ({res.status_code}):", res.text)
        except Exception as e:
            print("⚠ Gemini Exception:", str(e))
        time.sleep(delay)
    return None

# =====================
# ANALYSIS
# =====================
def analyze_url(url):
    if url in st.session_state.cache:
        return st.session_state.cache[url]

    if not VT_API_KEY:
        return {"level": "MEDIUM", "content": "⚠ VT_API_KEY is not set in environment."}

    headers = {"x-apikey": VT_API_KEY}

    try:
        # STEP 1: Try to fetch existing report using Base64 URL ID to save quota
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        stats = None
        if report_res.status_code == 200:
            report_data = report_res.json()
            stats = report_data["data"]["attributes"]["last_analysis_stats"]
        else:
            # STEP 2: Submit URL if no existing report
            res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            data = res.json()
            
            if res.status_code != 200 or "data" not in data:
                error_msg = data.get("error", {}).get("message", "API Limit Reached or Invalid Key.")
                return {"level": "MEDIUM", "content": f"VirusTotal Error: {error_msg}"}

            analysis_id = data["data"]["id"]

            # STEP 3: Poll for result
            for _ in range(8):
                time.sleep(3)
                poll_res = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )
                poll_data = poll_res.json()
                if "data" in poll_data and poll_data["data"]["attributes"]["status"] == "completed":
                    stats = poll_data["data"]["attributes"]["stats"]
                    break

        if not stats:
            return {"level": "MEDIUM", "content": "Analysis timed out. The URL might still be processing. Please try again later."}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # RISK LOGIC
        if malicious > 2:
            level = "HIGH"
        elif suspicious > 1 or malicious > 0:
            level = "MEDIUM"
        else:
            level = "LOW"

        # STEP 4: Explain with Gemini
        vt_stats = f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {stats.get('harmless', 0)}, Undetected: {stats.get('undetected', 0)}"
        prompt = f"""
You are an elite cybersecurity analyst. 
I have analyzed the following URL: {url}
The VirusTotal API returned the following engine detection stats: {vt_stats}.
The calculated threat level is: {level}.

STRICT FORMAT REQUIREMENTS - Output EXACTLY this format:

Threat Level: {level}

Explanation:
<Provide a formal, professional 2-3 sentence explanation of what these specific results mean regarding the safety of the URL>

Key Risks:
- <Risk 1>
- <Risk 2>

Recommendations:
- <Recommendation 1>
- <Recommendation 2>
"""
        explanation = call_gemini(prompt)

        content = explanation if explanation else f"Threat Level: {level}\n\nExplanation:\n{malicious} security vendors flagged this as malicious and {suspicious} as suspicious."

        # Remove the explicit Threat Level line to avoid duplication with UI badge
        content = re.sub(r'Threat Level:\s*(HIGH|MEDIUM|LOW)\s*\n*', '', content, flags=re.IGNORECASE)

        final = {"level": level, "content": content.strip()}
        st.session_state.cache[url] = final
        return final

    except Exception as e:
        return {"level": "MEDIUM", "content": f"Connection error occurred during analysis: {str(e)}"}


def analyze_text(text, mode="TEXT"):
    if text in st.session_state.cache:
        return st.session_state.cache[text]

    prompt = f"""
You are an elite cybersecurity AI.
Analyze the following {mode.lower()} for phishing, social engineering, scams, or malicious intent.

STRICT FORMAT REQUIREMENTS - Output EXACTLY in this format:

Threat Level: [LOW or MEDIUM or HIGH]

Explanation:
<A clear, formal, and precise explanation of why this level was assigned>

Key Risks:
- <Risk 1>
- <Risk 2>

Recommendations:
- <Recommendation 1>
- <Recommendation 2>

INPUT TO ANALYZE:
{text}
"""
    res = call_gemini(prompt)

    if not res:
         return {"level": "MEDIUM", "content": "Analysis temporarily unavailable. Please check API connectivity."}

    # Extract level securely
    match = re.search(r'Threat Level:\s*(HIGH|MEDIUM|LOW)', res, re.IGNORECASE)
    if match:
        level = match.group(1).upper()
    else:
        level = "LOW"
        if "HIGH" in res.upper(): level = "HIGH"
        elif "MEDIUM" in res.upper(): level = "MEDIUM"

    # Remove the explicit Threat Level text so it doesn't double-render with the badge
    res = re.sub(r'Threat Level:\s*(HIGH|MEDIUM|LOW)\s*\n*', '', res, flags=re.IGNORECASE)

    data = {"level": level, "content": res.strip()}
    st.session_state.cache[text] = data
    return data

# =====================
# SIDEBAR
# =====================
st.sidebar.title("🛡️ CyberSentinel")
st.sidebar.markdown("<p style='color: #94a3b8; font-size: 14px; margin-bottom: 20px;'>Select Analysis Mode</p>", unsafe_allow_html=True)

if st.sidebar.button("🔗 URL Intelligence", type="primary" if st.session_state.mode == "URL" else "secondary"):
    st.session_state.mode = "URL"
    st.rerun()

if st.sidebar.button("📧 Email Intelligence", type="primary" if st.session_state.mode == "EMAIL" else "secondary"):
    st.session_state.mode = "EMAIL"
    st.rerun()

if st.sidebar.button("💬 Text Intelligence", type="primary" if st.session_state.mode == "TEXT" else "secondary"):
    st.session_state.mode = "TEXT"
    st.rerun()

st.sidebar.markdown(f"""
<div style='margin-top: 30px; padding: 15px; background: #1e293b; border-radius: 10px; border-left: 4px solid #00f5ff;'>
    <p style='margin:0; font-size: 13px; color: #cbd5e1;'>Active Mode</p>
    <p style='margin:0; font-weight: bold; font-size: 18px; color: #fff;'>{st.session_state.mode}</p>
</div>
""", unsafe_allow_html=True)

# =====================
# TITLE
# =====================
st.markdown("""
<div class='title'>
    <h1>AI Powered Threat Detection</h1>
    <p>Real-time AI threat analysis  <br/>    Hunt threats before they hunt you</p>
</div>
""", unsafe_allow_html=True)

# =====================
# CHAT CONTAINER
# =====================
st.markdown("<div class='chat-container'>", unsafe_allow_html=True)

for m in st.session_state.messages:
    if m["role"] == "user":
        st.markdown(f"<div class='chat-bubble user-bubble'>{html.escape(m['content'])}</div>", unsafe_allow_html=True)
    else:
        lvl = m["level"].lower()
        icon = "🟢" if lvl == "low" else "🟠" if lvl == "medium" else "🔴"
        formatted_text = format_markdown(m['content'])
        
        st.markdown(f"""
        <div class='chat-bubble ai-bubble'>
            <div class='badge {lvl}'>
                <span class='badge-icon'>{icon}</span> {m['level']} RISK DETECTED
            </div>
            <div>{formatted_text}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

# =====================
# INPUT
# =====================
placeholder = {
    "URL": "Enter suspicious URL or domain (e.g., example.com)...",
    "EMAIL": "Paste full email headers or content here...",
    "TEXT": "Paste suspicious text message, post, or content..."
}[st.session_state.mode]

user_input = st.chat_input(placeholder)

if user_input:
    st.session_state.messages.append({"role": "user", "content": user_input})

    with st.spinner(f"Analyzing {st.session_state.mode.lower()} for threats..."):
        if st.session_state.mode == "URL":
            result = analyze_url(user_input)
        else:
            result = analyze_text(user_input, mode=st.session_state.mode)

    if not result:
        st.session_state.messages.append({
            "role": "ai",
            "content": "Analysis temporarily unavailable. Please try again.",
            "level": "MEDIUM"
        })
    else:
        st.session_state.messages.append({
            "role": "ai",
            "content": result["content"],
            "level": result["level"]
        })

    st.rerun()