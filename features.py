"""Feature extraction.

IMPORTANT: the numbers produced here must stay IDENTICAL to what the model was
trained on (see the notebook). If you change the maths of any feature you must
retrain the model, otherwise predictions silently become wrong.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# suffix_list_urls=() -> use the bundled public-suffix snapshot, never hit the network
extractor = tldextract.TLDExtract(suffix_list_urls=())

KW = ["login", "signin", "secure", "account", "update", "verify", "bank", "paypal",
      "confirm", "free", "bonus", "webscr", "support", "wallet", "password",
      "service", "ebay", "apple", "microsoft"]


def ent(s):
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def base_features(u):
    p = urlparse(u)
    e = extractor(u)
    dom = e.domain + ("." + e.suffix if e.suffix else "")
    sub = len(e.subdomain.split(".")) if e.subdomain else 0
    L = sum(c.isalpha() for c in u)
    D = sum(c.isdigit() for c in u)
    S = len(u) - L - D
    return {
        "url_len": len(u), "dom_len": len(dom),
        "tld_len": len(e.suffix), "subdom_cnt": sub, "letter_cnt": L,
        "digit_cnt": D, "special_cnt": S, "eq_cnt": u.count("="),
        "qm_cnt": u.count("?"), "amp_cnt": u.count("&"), "dot_cnt": u.count("."),
        "dash_cnt": u.count("-"), "under_cnt": u.count("_"),
        "letter_ratio": L / len(u), "digit_ratio": D / len(u), "spec_ratio": S / len(u),
        "slash_cnt": u.count("/"),
        "entropy": ent(u), "path_len": len(p.path), "query_len": len(p.query),
    }


def url_features(u):
    s = re.sub(r"^https?://", "", u, flags=re.I)
    host, _, rest = s.partition("/")
    host = host.split(":")[0]
    path, _, q = rest.partition("?")
    labels = host.split(".")
    hd = sum(ch.isdigit() for ch in host)
    low = u.lower()
    digit_runs = re.findall(r"\d+", u)
    cons_runs = re.findall(r"[^aeiou\W\d_]+", host.lower())
    return {
        "host_len": len(host), "host_digits": hd,
        "host_digit_ratio": hd / max(len(host), 1), "host_dash": host.count("-"),
        "host_vowel_ratio": sum(ch in "aeiou" for ch in host) / max(len(host), 1),
        "host_entropy": ent(host), "path_entropy": ent(path), "query_entropy": ent(q),
        "longest_label": max(len(x) for x in labels), "n_labels": len(labels),
        "path_depth": path.count("/") + (1 if path else 0),
        "has_www": int(host.startswith("www.")), "has_at": int("@" in u),
        "double_slash_path": int("//" in rest), "pct_enc": u.count("%"),
        "kw_count": sum(k in low for k in KW),
        "kw_in_host": sum(k in host.lower() for k in KW),
        "path_dash": path.count("-"), "path_under": path.count("_"),
        "path_digits": sum(ch.isdigit() for ch in path),
        "max_digit_run": max((len(r) for r in digit_runs), default=0),
        "max_cons_run": max((len(r) for r in cons_runs), default=0),
        "file_ext_script": int(bool(re.search(r"\.(php|asp|aspx|jsp|cgi)(\?|$|/)", low))),
        "file_ext_html": int(bool(re.search(r"\.html?(\?|$)", low))),
        "n_params": (q.count("&") + 1) if q else 0,
    }
