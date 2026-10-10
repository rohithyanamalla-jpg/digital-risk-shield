import re

PATTERNS = {
    "Asks for OTP, PIN or password": r"\b(otp|pin|password|cvv)\b",
    "Creates urgency or threat": r"\b(urgent|expiring|expires|suspended|blocked|block|immediately|today)\b",
    "Promises money or rewards": r"\b(won|winner|cashback|reward|congratulations|prize|lottery)\b",
    "Asks for a fee or payment": r"(processing fee|send rs|pay rs|transfer|upi id)",
    "Mentions KYC or refund bait": r"\b(kyc|refund)\b",
}
SHORTENERS = ["bit.ly", "tinyurl.com", "wa.me", "cutt.ly", "t.co"]
BAD_TLDS = [".xyz", ".top", ".click", ".info", ".online"]
WEIGHTS = {
    "Asks for OTP, PIN or password": 30,
    "Creates urgency or threat": 15,
    "Promises money or rewards": 20,
    "Asks for a fee or payment": 40,
    "Mentions KYC or refund bait": 15,
}


def analyze_message(text, brand):
    text_l = str(text).lower()
    score = 0
    reasons = []

    # Safety-advice messages ("we will never ask for OTP") are not scams
    if "never ask" in text_l or "will never" in text_l:
        return 0, ["Message is a safety warning, not a request"]

    for label, pattern in PATTERNS.items():
        if re.search(pattern, text_l):
            score += WEIGHTS[label]
            reasons.append(label)

    urls = re.findall(r"(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/\S*)?", text_l)
    for u in urls:
        if brand["official_website"] in u:
            continue
        if any(s in u for s in SHORTENERS):
            score += 30
            reasons.append(f"Shortened link: {u}")
        elif any(t in u for t in BAD_TLDS):
            score += 30
            reasons.append(f"Lookalike or risky domain: {u}")

    return min(100, score), reasons


def message_label(score):
    if score >= 50:
        return "SCAM"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"
