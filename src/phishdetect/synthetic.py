"""Original hand-written synthetic URL patterns; never real-world ground truth.

Generated domains are illustrative strings and may coincidentally exist.
No generated URL is ever visited.
"""
import random
import string

WORDS = ["shop", "news", "learn", "travel", "photo", "cloud", "tech", "health",
         "food", "sports", "music", "books", "game", "design", "market", "city",
         "river", "garden", "studio", "pixel", "orbit", "maple", "delta", "nova"]
LEGIT_TLDS = ["com", "org", "net", "edu", "io", "co", "com.bd", "org.bd", "gov.bd", "info"]
BAD_TLDS = ["top", "xyz", "tk", "ml", "ga", "click", "work", "icu", "buzz", "com", "net", "info"]
BRANDS = ["paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix",
          "bkash", "nagad", "instagram", "whatsapp", "dutchbangla"]
LURES = ["login", "signin", "verify", "update", "secure", "account", "confirm",
         "billing", "password", "unlock", "support"]
PATHS = ["index", "about", "blog", "products", "contact", "article", "category",
         "post", "docs", "help", "pricing", "events"]


def rnd(n: int) -> str:
    """Create a random lexical identifier."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def word() -> str:
    """Choose a neutral word."""
    return random.choice(WORDS)


def legit() -> str:
    """Generate a benign-pattern URL, including ambiguous cases."""
    domain = random.choice([word(), word() + word(), word() + "-" + word()])
    host = f"{domain}.{random.choice(LEGIT_TLDS)}"
    if random.random() < 0.35:
        host = random.choice(["www", "blog", "mail", "docs", "shop", "app"]) + "." + host
    # Ambiguous: some legit sites mention brands / use login pages / have long URLs
    path = "/" + "/".join(random.choices(PATHS, k=random.randint(0, 3)))
    if random.random() < 0.12:
        path += "/" + random.choice(LURES)
    if random.random() < 0.2:
        path += f"?id={random.randint(1, 99999)}&ref={word()}"
    if random.random() < 0.03:
        host = random.choice(BRANDS) + ".com"
    scheme = "https" if random.random() < 0.88 else "http"
    return f"{scheme}://{host}{path}"


def phishing() -> str:
    """Generate a phishing-pattern URL, including clean-looking cases."""
    kind = random.random()
    brand = random.choice(BRANDS)
    lure = random.choice(LURES)
    if kind < 0.18:  # raw IP host
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        url = f"http://{ip}/{lure}/{brand}/{rnd(6)}.php"
    elif kind < 0.50:  # brand in subdomain of throwaway domain
        base = f"{random.choice(LURES)}-{rnd(random.randint(4, 9))}.{random.choice(BAD_TLDS)}"
        url = f"http://{brand}.{lure}.{base}/{lure}?session={rnd(16)}"
    elif kind < 0.68:  # brand in path on a hacked-looking site
        url = f"http://{word()}{rnd(3)}.{random.choice(BAD_TLDS)}/wp-content/{brand}/{lure}/index.php?email={rnd(6)}"
    elif kind < 0.80:  # hyphen-stuffed look-alike domain
        url = f"http://{brand}-{lure}-{word()}.{random.choice(BAD_TLDS)}/"
    elif kind < 0.88:  # @ trick
        url = f"http://{brand}.com@{rnd(8)}.{random.choice(BAD_TLDS)}/{lure}"
    elif kind < 0.94:  # punycode
        url = f"http://xn--{rnd(7)}-{rnd(3)}.{random.choice(BAD_TLDS)}/{lure}"
    else:  # stealthy: clean-looking, hard cases
        url = f"https://{word()}{word()}.{random.choice(['com', 'net', 'info'])}/{random.choice(PATHS)}"
    if random.random() < 0.25 and url.startswith("http://"):
        url = "https://" + url[len("http://"):]  # attackers use HTTPS too
    return url

