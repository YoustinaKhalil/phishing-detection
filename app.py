"""Streamlit front-end. Start the API first (uvicorn main:app), then: streamlit run app.py"""
import html
import os

import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/predict")

st.set_page_config(page_title="Link Checker", page_icon="🛡️", layout="centered",
                   initial_sidebar_state="collapsed")

st.html("""
<style>
#MainMenu, footer {visibility: hidden;}
header[data-testid="stHeader"] {background: transparent;}
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {display: none;}
.block-container {padding-top: 4rem; max-width: 720px;}
.hero {text-align: center; margin-bottom: 2rem;}
.hero .logo {font-size: 4rem; line-height: 1;}
.hero h1 {margin: .6rem 0 .4rem 0; font-size: 2.6rem; font-weight: 800; letter-spacing: -.5px;
  background: linear-gradient(90deg, #60a5fa, #a78bfa, #f472b6);
  -webkit-background-clip: text; background-clip: text; color: transparent;}
.hero p {margin: 0; opacity: .75; font-size: 1.1rem;}
div[data-testid="stTextInput"] input {border-radius: 14px; padding: .9rem 1.1rem; font-size: 1.05rem;}
div[data-testid="stFormSubmitButton"] button {border-radius: 14px; font-weight: 700; padding: .65rem 0; font-size: 1.05rem;}
.result {border-radius: 20px; padding: 2rem 1.8rem; text-align: center; border: 1px solid; margin-top: 1.5rem;}
.safe    {background: rgba(34,197,94,.10);  border-color: rgba(34,197,94,.55);}
.warn    {background: rgba(245,158,11,.10); border-color: rgba(245,158,11,.60);}
.unsafe  {background: rgba(239,68,68,.10);  border-color: rgba(239,68,68,.55);}
.invalid {background: rgba(148,163,184,.10); border-color: rgba(148,163,184,.55);}
.result .icon {font-size: 3.6rem; line-height: 1;}
.result h2 {margin: .6rem 0 .3rem 0; font-size: 2rem; font-weight: 800;}
.result .desc {opacity: .85; font-size: 1.05rem;}
.result ul {text-align: left; margin: 1rem auto 0; max-width: 560px; opacity: .9; font-size: .95rem;}
.result .url {margin-top: 1.1rem; font-family: ui-monospace, monospace; font-size: .85rem; opacity: .7;
  word-break: break-all; background: rgba(0,0,0,.25); padding: .55rem .8rem; border-radius: 10px;}
.note {text-align: center; opacity: .5; font-size: .85rem; margin-top: 1.6rem;}
</style>
""")

st.html(
    '<div class="hero"><div class="logo">🛡️</div><h1>Is this link safe?</h1>'
    "<p>Paste any link below and we'll tell you if it's safe to open.</p></div>"
)

# verdict -> (css class, icon, title, description)
CARDS = {
    "safe": ("safe", "✅", "Looks safe",
             "No warning signs found. Still, never enter passwords on a page you reached from a message."),
    "suspicious": ("warn", "⚠️", "Be careful",
                   "We found things that look unusual. Don't enter passwords or personal info unless you are sure."),
    "phishing": ("unsafe", "🚨", "Not safe",
                 "This link looks like phishing. Don't open it or enter any passwords or personal info."),
}


def card(css, icon, title, desc, url="", reasons=()):
    items = "".join(f"<li>{html.escape(r)}</li>" for r in reasons)
    st.html(
        f'<div class="result {css}"><div class="icon">{icon}</div><h2>{html.escape(title)}</h2>'
        f'<div class="desc">{html.escape(desc)}</div>'
        + (f"<ul>{items}</ul>" if items else "")
        + (f'<div class="url">{html.escape(url)}</div>' if url else "")
        + "</div>"
    )


with st.form("check", border=False):
    url = st.text_input("Link", placeholder="Paste a link here, e.g. https://example.com",
                        label_visibility="collapsed")
    submitted = st.form_submit_button("Check link", type="primary", width="stretch")

if submitted:
    if not url.strip():
        st.warning("Please paste a link first.")
    else:
        try:
            with st.spinner("Checking…"):
                response = requests.post(API_URL, json={"url": url.strip()}, timeout=30)
            if response.status_code == 422:      # input is not a link (e.g. Arabic sentence)
                detail = response.json().get("detail", {})
                msg = detail.get("message", "That doesn't look like a link.") if isinstance(detail, dict) else str(detail)
                card("invalid", "🤔", "That doesn't look like a link", msg)
            else:
                response.raise_for_status()
                r = response.json()
                css, icon, title, desc = CARDS[r["verdict"]]
                card(css, icon, title, desc, url=r["url"], reasons=r.get("reasons", []))
                if r.get("score") is not None:
                    st.caption(f"Model score: {r['score']:.2f}  (0 = looks normal, 1 = looks like phishing)")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to the API. Please make sure it is running (uvicorn main:app).")
        except requests.exceptions.Timeout:
            st.error("The API request timed out. Please try again.")
        except requests.exceptions.HTTPError:
            st.error("The server had a problem checking this link. Please try again.")
        except Exception as e:  # noqa: BLE001
            st.error(f"Unexpected error: {e}")

st.html('<div class="note">No checker is 100% accurate — if something feels off, don\'t click.</div>')
