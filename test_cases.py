"""Run:  python test_cases.py      (needs the .pkl files next to it, no server needed)

Each case: (what the user typed, expected verdict)  or  (input, "invalid:<code>")
"""
import sys
import warnings

warnings.filterwarnings("ignore")
from detector import InvalidURL, analyze  # noqa: E402

CASES = [
    # --- not links: must be rejected, never "safe" --------------------------------
    ("كلام عربي", "invalid:not_a_url"),
    ("مرحبا", "invalid:no_tld"),
    ("hello world", "invalid:not_a_url"),
    ("google", "invalid:no_tld"),
    ("1234", "invalid:not_a_url"),
    ("   ", "invalid:empty"),
    ("http://", "invalid:no_host"),
    ("javascript:alert(1)", "invalid:bad_scheme"),
    ("ftp://example.com/file", "invalid:bad_scheme"),
    ("http://a..com", "invalid:bad_host"),
    # --- normal sites (also typed without http://) --------------------------------
    ("www.google.com", "safe"),
    ("HTTPS://WWW.GOOGLE.COM/", "safe"),
    ("https://github.com/torvalds/linux", "safe"),
    ("https://stackoverflow.com/questions/123/how-to", "safe"),
    ("https://www.google.com/search?q=مرحبا", "safe"),        # Arabic in the query is fine
    # --- attacks -------------------------------------------------------------------
    ("http://paypal.com@evil.xyz/", "phishing"),
    ("http://paypal.com.secure-login.xyz/", "phishing"),
    ("https://paypаl.com/login", "phishing"),                 # Cyrillic 'а' look-alike
    ("http://0x7f.0.0.1/", "phishing"),
    ("paypal-verify-login.xyz/secure/update.php", "phishing"),
    # --- model can't judge: must be "suspicious", not "safe" -----------------------
    ("http://1.2.3.4/", "suspicious"),
    ("http://bit.ly/3xYz", "suspicious"),
    ("مثال.com", "suspicious"),                                # Arabic domain name
    ("\u200bhttp://google.com", "suspicious"),                # hidden character
]

bad = 0
for text, expected in CASES:
    try:
        got = analyze(text)["verdict"]
    except InvalidURL as e:
        got = f"invalid:{e.code}"
    ok = got == expected
    bad += not ok
    print(f"{'OK  ' if ok else 'FAIL'} {text[:48]!r:52} expected={expected:22} got={got}")

print(f"\n{len(CASES) - bad}/{len(CASES)} passed")
sys.exit(1 if bad else 0)
