from rapidfuzz import fuzz

# Characters scammers swap to imitate letters
LOOKALIKES = {"1": "i", "l": "i", "0": "o", "5": "s", "3": "e", "rn": "m"}
SUSPICIOUS_WORDS = ["support", "help", "care", "rewards", "refund",
                    "official", "kyc", "cashback", "offer", "claim"]
SHORTENERS = ["bit.ly", "tinyurl.com", "wa.me", "t.co", "cutt.ly"]
BAD_TLDS = [".xyz", ".top", ".click", ".info", ".online"]
SCAM_BIO_WORDS = ["otp", "dm us", "click link", "limited offer",
                  "share otp", "account number", "kyc update", "claim"]


def normalize(text):
    """Lowercase and undo common character swaps (1->i, 0->o ...)."""
    text = str(text).lower()
    for fake, real in LOOKALIKES.items():
        text = text.replace(fake, real)
    return text.replace("_", "").replace(" ", "")


def analyze_profile(profile, brand):
    score = 0
    reasons = []

    handle = normalize(profile["handle"])
    official_handle = normalize(brand["official_handle"])
    name = normalize(profile["display_name"])
    official_name = normalize(brand["brand_name"])
    bio = str(profile["bio"]).lower()
    link = str(profile["link"]).lower() if str(profile["link"]) != "nan" else ""

    # The real account is never flagged
    if str(profile["handle"]).lower() == str(brand["official_handle"]).lower():
        return 0, ["Matches the official brand handle"]
        # 1. Handle similarity (brand keyword inside the handle, or close match)
    brand_key = normalize(brand["brand_name"]).replace("india", "")  # "safebank"
    handle_sim = fuzz.partial_ratio(handle, official_handle)
    if brand_key in handle or handle_sim >= 85:
        score += 30
        reasons.append(
            f"Handle imitates the brand (contains '{brand_key}' / {handle_sim:.0f}% similar)"
        )

    # 2. Display name similarity
    name_sim = fuzz.partial_ratio(name, official_name)
    if brand_key in name or name_sim >= 80:
        score += 20
        reasons.append(f"Display name imitates the brand name ({name_sim:.0f}% similar)")
   

    # 3. Suspicious words in handle
    found = [w for w in SUSPICIOUS_WORDS if w in str(profile["handle"]).lower()]
    if found and handle_sim >= 70:
        score += 10
        reasons.append(f"Handle contains scam-style words: {', '.join(found)}")

    # 4. Scam wording in bio
    bio_hits = [w for w in SCAM_BIO_WORDS if w in bio]
    if bio_hits:
        score += 15
        reasons.append(f"Bio uses scam-style wording: {', '.join(bio_hits)}")

    # 5. Link risk
    if any(s in link for s in SHORTENERS):
        score += 10
        reasons.append("Uses a shortened or messaging link instead of an official site")
    elif link and brand["official_website"] not in link:
        if any(t in link for t in BAD_TLDS):
            score += 10
            reasons.append("Link goes to a lookalike domain with a risky ending")

    # 6. Account behavior
    if profile["account_age_days"] < 30:
        score += 10
        reasons.append(f"Account is only {profile['account_age_days']} days old")
    if profile["followers"] > 0 and profile["following"] / profile["followers"] > 3:
        score += 5
        reasons.append("Follows far more accounts than follow it back")

    # 7. Safe signals reduce the score (protects innocent accounts)
    if "not affiliated" in bio or "unofficial" in bio:
        score -= 20
        reasons.append("Bio clearly states it is unofficial (reduces risk)")
    if profile["account_age_days"] > 365:
        score -= 10
        reasons.append("Long-standing account (reduces risk)")

    return max(0, min(100, score)), reasons


def risk_label(score):
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
