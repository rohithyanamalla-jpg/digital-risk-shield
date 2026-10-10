import streamlit as st
import pandas as pd
from detectors.message_detector import analyze_message, message_label
from detectors.profile_detector import analyze_profile, risk_label
from detectors.report import build_report

st.set_page_config(page_title="Digital Risk Shield", layout="wide")
st.title("Digital Risk Shield")
st.caption("Detecting fake profiles, scams and rogue apps for brands")

brands = pd.read_csv("data/brands.csv")
profiles = pd.read_csv("data/profiles.csv")
brand = brands.iloc[0]
tab1, tab2, tab3 = st.tabs(["Fake Profiles", "Scam Messages", "Takedown Report"])
with tab1:
    st.subheader(f"Fake Profile Detection for {brand['brand_name']}")
    # ... all the profile code, indented by 4 spaces
st.subheader(f"Fake Profile Detection for {brand['brand_name']}")

results = []
for _, p in profiles.iterrows():
    score, reasons = analyze_profile(p, brand)
    results.append({
        "handle": p["handle"],
        "risk_score": score,
        "risk": risk_label(score),
        "actual_fake": p["is_fake"],
        "reasons": reasons,
    })

res_df = pd.DataFrame(results).sort_values("risk_score", ascending=False)

st.dataframe(res_df.drop(columns=["reasons"]), use_container_width=True)

st.subheader("Why was each account flagged?")
for _, r in res_df.iterrows():
    with st.expander(f"@{r['handle']} - {r['risk']} ({r['risk_score']}/100)"):
        for reason in r["reasons"]:
            st.write("- " + reason)

# ---------- Accuracy panel ----------
st.subheader("Detector accuracy on demo data")
res_df["predicted_fake"] = res_df["risk"].isin(["HIGH", "MEDIUM"])
res_df["is_actually_fake"] = res_df["actual_fake"] == "yes"
correct = (res_df["predicted_fake"] == res_df["is_actually_fake"]).sum()
total = len(res_df)
c1, c2, c3 = st.columns(3)
c1.metric("Accounts scanned", total)
c2.metric("Correct verdicts", f"{correct}/{total}")
c3.metric("Accuracy", f"{correct / total * 100:.0f}%")

# ---------- Live checker ----------
st.subheader("Check any account live")
with st.form("live_check"):
    col1, col2 = st.columns(2)
    in_handle = col1.text_input("Handle", "safebank_helpdesk")
    in_name = col2.text_input("Display name", "SafeBank Help Desk")
    in_bio = st.text_area("Bio", "Contact us for refunds. Share OTP to verify.")
    in_link = st.text_input("Link", "bit.ly/sb-refund")
    col3, col4, col5 = st.columns(3)
    in_age = col3.number_input("Account age (days)", 0, 5000, 4)
    in_followers = col4.number_input("Followers", 0, 10000000, 120)
    in_following = col5.number_input("Following", 0, 10000000, 2500)
    submitted = st.form_submit_button("Analyze")

if submitted:
    test_profile = {
        "handle": in_handle, "display_name": in_name, "bio": in_bio,
        "link": in_link, "account_age_days": in_age,
        "followers": in_followers, "following": in_following,
    }
    s, why = analyze_profile(test_profile, brand)
    st.metric("Risk score", f"{s}/100", risk_label(s))
    for w in why:
        st.write("- " + w)
# ---------- Scam message detection ----------
st.header("Scam Message Detection")
messages = pd.read_csv("data/messages.csv")

msg_rows = []
for _, m in messages.iterrows():
    s, why = analyze_message(m["text"], brand)
    msg_rows.append({"text": m["text"], "score": s,
                     "verdict": message_label(s),
                     "actual_scam": m["is_scam"], "why": ", ".join(why)})
msg_df = pd.DataFrame(msg_rows)
st.dataframe(msg_df, use_container_width=True)

msg_df["pred"] = msg_df["verdict"] != "SAFE"
msg_df["real"] = msg_df["actual_scam"] == "yes"
ok = (msg_df["pred"] == msg_df["real"]).sum()
st.metric("Message detection accuracy", f"{ok}/{len(msg_df)}")

st.subheader("Check a message live")
user_msg = st.text_area("Paste a message",
    "Your SafeBank account is blocked. Share OTP at bit.ly/sb-unlock now")
if st.button("Check message"):
    s, why = analyze_message(user_msg, brand)
    st.metric("Scam score", f"{s}/100", message_label(s))
    for w in why:
        st.write("- " + w)
# ---------- Takedown report ----------
st.header("Takedown Report")
flagged = res_df[res_df["risk"].isin(["HIGH", "MEDIUM"])]
choice = st.selectbox("Select a flagged account", flagged["handle"])
row = flagged[flagged["handle"] == choice].iloc[0]
prof = profiles[profiles["handle"] == choice].iloc[0]
report = build_report(prof, brand, row["risk_score"], row["reasons"])
st.text_area("Generated report", report, height=320)
st.download_button("Download report", report, file_name=f"takedown_{choice}.txt")
