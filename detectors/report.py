from datetime import date


def build_report(profile, brand, score, reasons):
    evidence = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(reasons))
    return f"""IMPERSONATION / FRAUD REPORT
Date: {date.today().strftime('%d %B %Y')}

To: Trust & Safety Team
Reported account: @{profile['handle']}
Display name: {profile['display_name']}
Impersonated brand: {brand['brand_name']} (official handle: @{brand['official_handle']})
Risk score: {score}/100

Summary:
The above account is impersonating {brand['brand_name']} and appears to be
used for fraud. Evidence detected:
{evidence}

Request:
Please review and suspend this account for violating your impersonation
and fraud policies. The official brand account is @{brand['official_handle']}
(website: {brand['official_website']}).

Reported by: Digital Risk Shield on behalf of {brand['brand_name']}
"""
