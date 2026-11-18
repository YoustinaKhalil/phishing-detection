"""Everything that happens BEFORE and AROUND the ML model.

1. prepare_url()  - cleans the user's text and rejects anything that is not a real link
                    (Arabic sentences, "hello world", "google", javascript:..., etc.).
2. Safety flags   - rules the model cannot learn from its training data
                    (IP addresses, look-alike alphabets, "paypal.com@evil.com", ...).
3. Trusted list   - well-known domains, so long legit links (github.com/user/repo)
                    are not flagged just because they have a long path.
"""
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from features import extractor

MAX_URL_LEN = 2048  # the model was trained on URLs < 800 chars; longer is useless/abusive

# zero-width / direction-control characters that attackers use to disguise links
_INVISIBLE = {ord(c): None for c in
              "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\ufeff"}
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")
_BLOCKED_SCHEMES = {"javascript", "data", "vbscript", "file", "mailto", "tel", "ftp",
                    "blob", "about", "chrome", "view-source"}

# ----------------------------------------------------------------------------
# Lists (extend freely). Optional extra trusted domains: trusted_domains.txt,
# one registered domain per line (e.g. a Tranco top-10k export).
# ----------------------------------------------------------------------------
_BUILTIN_TRUSTED = {
    "google.com", "google.com.eg", "youtube.com", "facebook.com", "instagram.com",
    "whatsapp.com", "wikipedia.org", "github.com", "stackoverflow.com", "amazon.com",
    "microsoft.com", "live.com", "office.com", "apple.com", "linkedin.com", "x.com",
    "twitter.com", "reddit.com", "yahoo.com", "bing.com", "netflix.com", "zoom.us",
    "dropbox.com", "paypal.com", "ebay.com", "cloudflare.com", "mozilla.org",
    "python.org", "stackexchange.com", "anthropic.com", "claude.ai", "openai.com", "kaggle.com",
    "vodafone.com.eg", "fawry.com", "cibeg.com", "nbe.com.eg", "banquemisr.com",
}
# anyone can publish content here, so "trusted domain" does NOT mean "trusted page"
_OPEN_PLATFORMS = {
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
    "storage.googleapis.com", "github.io", "blogspot.com", "web.app",
    "firebaseapp.com", "weebly.com", "wixsite.com", "netlify.app", "pages.dev",
    "workers.dev", "herokuapp.com", "notion.site", "vercel.app", "glitch.me",
}
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly",
               "cutt.ly", "rb.gy", "shorturl.at", "t.ly"}
_BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "facebook",
           "instagram", "netflix", "whatsapp", "ebay", "vodafone", "fawry", "instapay"]


def _load_trusted() -> set:
    trusted = set(_BUILTIN_TRUSTED)
    extra = Path(__file__).with_name("trusted_domains.txt")
    if extra.exists():
        for line in extra.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                trusted.add(line)
    return trusted


TRUSTED = _load_trusted()


class InvalidURL(ValueError):
    """The input is not a checkable link. `code` is machine-readable, `message` is for humans."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Prepared:
    url: str                 # cleaned URL - exactly what the model will see
    host: str
    registered_domain: str
    is_ip: bool = False
    trusted: bool = False
    shortener: bool = False
    flags: list = field(default_factory=list)  # [("high" | "medium", "message"), ...]


def _label_scripts(label: str) -> set:
    return {unicodedata.name(c, "?").split()[0] for c in label if c.isalpha()}


def _host_in(host: str, domains: set) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def prepare_url(raw: str) -> Prepared:
    """Return a cleaned URL + risk flags, or raise InvalidURL."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidURL("empty", "Please paste a link first.")

    flags = []
    cleaned = raw.translate(_INVISIBLE)
    if cleaned != raw:
        flags.append(("medium", "The link contained hidden characters, a trick used to disguise links."))
    u = cleaned.strip()

    if len(u) > MAX_URL_LEN:
        raise InvalidURL("too_long", f"This link is too long to check (max {MAX_URL_LEN} characters).")
    if re.search(r"\s", u) or any(unicodedata.category(c) == "Cc" for c in u):
        raise InvalidURL("not_a_url", "This looks like normal text, not a link. "
                                      "Links can't contain spaces - paste just the link.")

    # ---- scheme -----------------------------------------------------------
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(//)?", u)
    scheme = m.group(1).lower() if m else None
    if m and (m.group(2) or scheme in _BLOCKED_SCHEMES):
        if scheme not in ("http", "https"):
            raise InvalidURL("bad_scheme", f"Only http:// and https:// links can be checked "
                                           f"(this one starts with '{scheme}:').")
    elif u.startswith("//"):
        u = "http:" + u
    else:  # "example.com", "example.com:8080/x"
        u = "http://" + u

    # ---- split ------------------------------------------------------------
    try:
        parts = urlsplit(u)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise InvalidURL("malformed", "This link is malformed (check the port number and brackets).")
    if not host:
        raise InvalidURL("no_host", "I couldn't find a website address in this text.")
    host = host.rstrip(".")
    if not host:
        raise InvalidURL("no_host", "I couldn't find a website address in this text.")

    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""

    # ---- IP addresses -----------------------------------------------------
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass

    if ip is not None:
        if ip.is_global:
            flags.append(("medium", "The link uses a raw IP address instead of a website name."))
        else:
            flags.append(("medium", "This is a private/local address, not a public website."))
        shown = f"[{host}]" if ip.version == 6 else host
        return _finish(parts, shown, host, "", True, False, userinfo, port, flags)

    if _NUMERIC_HOST.fullmatch(host):
        if "." not in host and not host.startswith("0x") and len(host) < 8:
            raise InvalidURL("not_a_url", "That looks like a number, not a website address.")
        flags.append(("high", "The address is an IP written in a disguised number format."))
        return _finish(parts, host, host, "", True, False, userinfo, port, flags)

    # ---- domain name (incl. Arabic / international names) ------------------
    if host.isascii():
        ascii_host = host
    else:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidURL("bad_host", "The domain name contains characters that aren't allowed.")

    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or not all(_LABEL.fullmatch(l) for l in labels):
        raise InvalidURL("bad_host", "That isn't a valid website address "
                                     "(check for typos, spaces or unusual characters).")

    ext = extractor(ascii_host)
    if not ext.suffix or not ext.domain:
        raise InvalidURL("no_tld", "That doesn't look like a website address - it needs a valid "
                                   "ending such as .com or .eg (e.g. example.com).")

    if any(l.startswith("xn--") for l in labels):
        try:
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except UnicodeError:
            raise InvalidURL("bad_host", "The domain name is not valid.")
        if any(len(_label_scripts(l)) > 1 for l in unicode_host.split(".")):
            flags.append(("high", "The domain mixes different alphabets (e.g. Arabic/Cyrillic with "
                                  "Latin) - a classic look-alike trick."))
        else:
            flags.append(("medium", "The domain uses non-English letters. The model was trained on "
                                    "English-alphabet links only, so it can't judge these reliably."))

    registered = f"{ext.domain}.{ext.suffix}"

    # ---- rule-based flags ---------------------------------------------------
    if userinfo:
        level = "high" if "." in userinfo else "medium"
        flags.append((level, "The link has a 'name@' part before the real address - attackers use "
                             "it to make a fake site look like a real one."))
    if ext.subdomain and ext.subdomain.count(".") + 1 >= 4:
        flags.append(("medium", "The link has an unusually large number of subdomains."))

    on_open_platform = _host_in(ascii_host, _OPEN_PLATFORMS)
    shortener = _host_in(ascii_host, _SHORTENERS)
    if shortener:
        flags.append(("medium", "This is a shortened link - the real destination is hidden."))
    elif on_open_platform:
        flags.append(("medium", "This site is on a free hosting/publishing platform where anyone "
                                "can create pages."))

    tokens = set(re.split(r"[.\-_]", ascii_host))
    for brand in _BRANDS:
        if brand in tokens and ext.domain != brand:
            if re.search(rf"\b{brand}\.(com|net|org|co)\b", ascii_host):
                flags.append(("high", f"The address pretends to be '{brand}.com' but belongs to "
                                      f"another site ({registered})."))
            else:
                flags.append(("medium", f"The address uses the name '{brand}' but is not the "
                                        f"official '{brand}' site."))
            break

    trusted = registered in TRUSTED and not on_open_platform and not shortener and not userinfo
    prep = _finish(parts, ascii_host, ascii_host, registered, False, trusted, userinfo, port, flags)
    prep.shortener = shortener
    return prep


def _finish(parts, shown_host, host, registered, is_ip, trusted, userinfo, port, flags) -> Prepared:
    """Rebuild a canonical URL in the same shape as the training data (http(s)://host/path?query)."""
    netloc = (userinfo + "@" if userinfo else "") + shown_host + (f":{port}" if port else "")
    path = parts.path or "/"          # training URLs always have at least "/"
    query = f"?{parts.query}" if parts.query else ""
    url = f"{parts.scheme}://{netloc}{path}{query}"   # fragment (#...) is never sent to servers -> dropped
    return Prepared(url=url, host=host, registered_domain=registered,
                    is_ip=is_ip, trusted=trusted, flags=flags)
