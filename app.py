import re
import streamlit as st

st.set_page_config(
    page_title="PrivacyLens",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 PrivacyLens")
st.subheader("AI-Powered Privacy Risk Detection and Protection")

st.write(
    "Check your text for sensitive information before sharing it."
)

text = st.text_area(
    "Paste your text here:",
    height=200,
    placeholder="Enter text containing an email address or phone number..."
)

if st.button("Scan for Privacy Risks"):
    if not text.strip():
        st.warning("Please enter some text first.")
    else:
        findings = []

        patterns = {
            "Email Address": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
            "Phone Number": r"(?<!\w)(?:\+?\d[\d\s()-]{7,}\d)(?!\w)"
        }

        for label, pattern in patterns.items():
            for match in re.finditer(pattern, text):
                findings.append({
                    "type": label,
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end()
                })

        if findings:
            st.error(f"Found {len(findings)} potential privacy risks.")

            for item in findings:
                st.write(f"**{item['type']}:** {item['value']}")

            protected_text = text

            for item in sorted(
                findings,
                key=lambda item: item["start"],
                reverse=True
            ):
                protected_text = (
                    protected_text[:item["start"]]
                    + f"[{item['type'].upper()} REDACTED]"
                    + protected_text[item["end"]:]
                )

            st.subheader("Privacy-Protected Text")
            st.code(protected_text)

            st.download_button(
                "Download Protected Text",
                data=protected_text,
                file_name="protected_text.txt",
                mime="text/plain"
            )
        else:
            st.success("No email addresses or phone numbers detected.")
