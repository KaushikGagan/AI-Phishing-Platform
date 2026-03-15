"""
AI-Powered Phishing Detection Dashboard — Streamlit UI
"""
import sys
import os
import json
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import process_email, load_and_process_sample
from nlp_engine.phishing_detector import train_model

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e, #252d3d);
        border-radius: 12px; padding: 20px; text-align: center;
        border: 1px solid #2d3748;
    }
    .risk-high { color: #e74c3c; font-weight: bold; font-size: 1.2em; }
    .risk-suspicious { color: #f39c12; font-weight: bold; font-size: 1.2em; }
    .risk-safe { color: #2ecc71; font-weight: bold; font-size: 1.2em; }
    .stAlert { border-radius: 8px; }
    .flag-badge {
        background: #2d3748; border-radius: 6px; padding: 3px 8px;
        margin: 2px; display: inline-block; font-size: 0.8em;
    }
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = []
if "model_trained" not in st.session_state:
    st.session_state.model_trained = False


@st.cache_resource(show_spinner=False)
def get_trained_model():
    pipeline, report, cm = train_model(save=True)
    return pipeline, report, cm


def risk_badge(level: str) -> str:
    colors = {"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"}
    labels = {"safe": "✅ SAFE", "suspicious": "⚠️ SUSPICIOUS", "high_risk": "🚨 HIGH RISK"}
    c = colors.get(level, "#95a5a6")
    l = labels.get(level, level.upper())
    return f'<span style="background:{c};color:#000;padding:3px 10px;border-radius:12px;font-weight:bold;font-size:0.85em">{l}</span>'


def score_gauge(score: float, title: str = "Risk Score"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"color": "white", "size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "white"},
            "bar": {"color": "#e74c3c" if score > 60 else "#f39c12" if score > 30 else "#2ecc71"},
            "steps": [
                {"range": [0, 30], "color": "#1a2e1a"},
                {"range": [30, 60], "color": "#2e2a1a"},
                {"range": [60, 100], "color": "#2e1a1a"},
            ],
            "threshold": {"line": {"color": "white", "width": 2}, "value": score}
        },
        number={"font": {"color": "white"}}
    ))
    fig.update_layout(
        height=200, margin=dict(l=20, r=20, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
    )
    return fig


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=60)
    st.title("PhishGuard AI")
    st.caption("AI-Powered Phishing Detection Platform")
    st.divider()

    page = st.radio("Navigation", [
        "🏠 Dashboard", "📧 Scan Email", "🔗 URL Analyzer",
        "📊 Analytics", "🤖 Model Info", "📄 Reports"
    ])
    st.divider()

    if st.button("🔄 Load Sample Emails", use_container_width=True):
        with st.spinner("Processing sample emails..."):
            st.session_state.results = load_and_process_sample()
        st.success(f"Loaded {len(st.session_state.results)} emails")

    st.caption(f"Model status: {'✅ Ready' if st.session_state.model_trained else '⏳ Loading'}")


# ── Pre-load model ─────────────────────────────────────────────────────────────
with st.spinner("Initializing AI models..."):
    pipeline, model_report, cm = get_trained_model()
    st.session_state.model_trained = True

results = st.session_state.results

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Dashboard":
    st.title("🛡️ PhishGuard AI — Threat Intelligence Dashboard")
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if not results:
        st.info("👈 Click **Load Sample Emails** in the sidebar to populate the dashboard.")
        st.stop()

    df = pd.DataFrame([{
        "id": r["email_id"],
        "sender": r["sender"],
        "subject": r["subject"][:50] + "..." if len(r["subject"]) > 50 else r["subject"],
        "risk_level": r["risk_report"]["risk_level"],
        "final_score": r["risk_report"]["final_score"],
        "language": r["language"],
        "timestamp": r["timestamp"],
    } for r in results])

    # KPI row
    total = len(df)
    high_risk = len(df[df.risk_level == "high_risk"])
    suspicious = len(df[df.risk_level == "suspicious"])
    safe = len(df[df.risk_level == "safe"])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📧 Total Scanned", total)
    c2.metric("🚨 High Risk", high_risk, delta=f"{high_risk/total*100:.0f}%", delta_color="inverse")
    c3.metric("⚠️ Suspicious", suspicious, delta=f"{suspicious/total*100:.0f}%", delta_color="inverse")
    c4.metric("✅ Safe", safe, delta=f"{safe/total*100:.0f}%")

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Risk Distribution")
        pie_df = df["risk_level"].value_counts().reset_index()
        pie_df.columns = ["Risk Level", "Count"]
        fig_pie = px.pie(
            pie_df, names="Risk Level", values="Count",
            color="Risk Level",
            color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"},
            hole=0.4
        )
        fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=300)
        st.plotly_chart(fig_pie, use_container_width=True, key="dash_pie")

    with col2:
        st.subheader("Language Distribution")
        lang_df = df["language"].value_counts().reset_index()
        lang_df.columns = ["Language", "Count"]
        fig_lang = px.bar(
            lang_df, x="Language", y="Count",
            color="Count", color_continuous_scale="Reds",
            text="Count"
        )
        fig_lang.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                                plot_bgcolor="rgba(0,0,0,0)", height=300)
        st.plotly_chart(fig_lang, use_container_width=True, key="dash_lang")

    st.subheader("Risk Score Distribution")
    fig_hist = px.histogram(
        df, x="final_score", nbins=10, color="risk_level",
        color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"},
        labels={"final_score": "Risk Score", "count": "Count"}
    )
    fig_hist.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                            plot_bgcolor="rgba(0,0,0,0)", height=250)
    st.plotly_chart(fig_hist, use_container_width=True, key="dash_hist")

    st.subheader("📋 Email Threat Table")
    for idx, r in enumerate(results):
        rr = r["risk_report"]
        badge_html = risk_badge(rr['risk_level'])
        label_text = {"safe": "SAFE", "suspicious": "SUSPICIOUS", "high_risk": "HIGH RISK"}.get(rr['risk_level'], rr['risk_level'].upper())
        expander_label = f"[{label_text}]  [{r['email_id']}]  {r['subject'][:55]}"
        with st.expander(expander_label, expanded=False):
            st.markdown(f"{badge_html} &nbsp; <b>{r['subject']}</b>", unsafe_allow_html=True)
            st.divider()
            c1, c2, c3 = st.columns([2, 2, 1])
            with c1:
                st.write(f"**From:** `{r['sender']}`")
                st.write(f"**Language:** {r['language'].title()}")
                st.write(f"**Time:** {r['timestamp']}")
            with c2:
                st.write(f"**NLP Score:** {rr['nlp_score']:.0f}/100")
                st.write(f"**URL Risk:** {rr['url_risk_score']:.0f}/100")
                st.write(f"**Anomaly:** {rr['anomaly_score']:.0f}/100")
            with c3:
                st.plotly_chart(score_gauge(rr["final_score"]), use_container_width=True, key=f"gauge_dash_{idx}")
            st.info(r["explanation"]["summary"])
            if rr["flags"]:
                st.write("**Flags:** " + " | ".join(f"`{f}`" for f in rr["flags"]))
            st.warning(f"**Action:** {rr['recommended_action']}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: SCAN EMAIL
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📧 Scan Email":
    st.title("📧 Real-Time Email Scanner")

    with st.form("email_form"):
        col1, col2 = st.columns(2)
        with col1:
            sender = st.text_input("Sender Email", placeholder="security@paypa1.com")
            sender_name = st.text_input("Sender Name", placeholder="PayPal Security")
        with col2:
            subject = st.text_input("Subject", placeholder="URGENT: Account suspended")
            timestamp = st.text_input("Timestamp", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        body = st.text_area("Email Body", height=150,
                            placeholder="Paste the email body here...")
        urls_input = st.text_input("URLs (comma-separated, optional)",
                                   placeholder="http://suspicious-link.xyz/login")
        submitted = st.form_submit_button("🔍 Analyze Email", use_container_width=True)

    if submitted and body:
        urls = [u.strip() for u in urls_input.split(",") if u.strip()] if urls_input else []
        email_data = {
            "id": f"SCAN-{datetime.now().strftime('%H%M%S')}",
            "sender": sender, "sender_name": sender_name,
            "subject": subject, "body": body,
            "timestamp": timestamp, "urls": urls
        }

        with st.spinner("🤖 Analyzing email through all detection modules..."):
            result = process_email(email_data)
            st.session_state.results.append(result)

        rr = result["risk_report"]
        exp = result["explanation"]

        st.divider()
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"### Result: {risk_badge(rr['risk_level'])}", unsafe_allow_html=True)
            st.markdown(f"**{exp['summary']}**")
            st.divider()

            st.subheader("Score Breakdown")
            score_cols = st.columns(4)
            score_cols[0].metric("NLP Score", f"{rr['nlp_score']:.0f}/100")
            score_cols[1].metric("URL Risk", f"{rr['url_risk_score']:.0f}/100")
            score_cols[2].metric("Anomaly", f"{rr['anomaly_score']:.0f}/100")
            score_cols[3].metric("Domain Rep", f"{rr['domain_reputation_score']:.0f}/100")

            if rr["flags"]:
                st.subheader("🚩 Detection Flags")
                for flag in rr["flags"]:
                    st.markdown(f'<span class="flag-badge">⚑ {flag}</span>', unsafe_allow_html=True)

            if result["url_results"]:
                st.subheader("🔗 URL Analysis")
                url_df = pd.DataFrame(result["url_results"])[
                    ["url", "label", "risk_score", "is_https", "suspicious_tld", "keyword_count"]
                ]
                st.dataframe(url_df, use_container_width=True)

            st.subheader("🌐 Language Detected")
            st.info(f"Language: **{result['language'].title()}**")

        with col2:
            st.plotly_chart(score_gauge(rr["final_score"], "Final Risk Score"), use_container_width=True, key="scan_final_gauge")
            if rr["risk_level"] == "high_risk":
                st.error(f"🚨 {rr['recommended_action']}")
            elif rr["risk_level"] == "suspicious":
                st.warning(f"⚠️ {rr['recommended_action']}")
            else:
                st.success(f"✅ {rr['recommended_action']}")

        with st.expander("🔬 Detailed Feature Analysis"):
            tf = result["text_features"]
            feat_df = pd.DataFrame([{
                "Feature": k.replace("_", " ").title(),
                "Value": v
            } for k, v in tf.items()])
            st.dataframe(feat_df, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: URL ANALYZER
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔗 URL Analyzer":
    st.title("🔗 URL Risk Analyzer")
    st.caption("Enter a URL below — all 19 features are calculated instantly.")

    from url_analysis.url_analyzer import analyze_url, analyze_urls_batch

    FEATURE_LABELS = {
        "url_length":        ("URL Length",         "Total character count of the URL"),
        "domain_length":     ("Domain Length",       "Character count of the domain part"),
        "num_dots":          ("Num Dots",            "Number of dots in the full URL"),
        "num_subdomains":    ("Num Subdomains",      "Subdomain levels beyond root domain"),
        "num_hyphens":       ("Num Hyphens",         "Hyphens in the domain name"),
        "num_slashes":       ("Num Slashes",         "Forward slashes in the URL"),
        "num_params":        ("Num Params",          "Query string parameters count"),
        "has_ip":            ("Has IP Address",      "IP used instead of domain name"),
        "is_https":          ("Is HTTPS",            "Uses secure HTTPS protocol"),
        "suspicious_tld":    ("Suspicious TLD",      "TLD is .xyz .tk .ml .ga etc."),
        "is_trusted_domain": ("Is Trusted Domain",   "Domain is in known-safe whitelist"),
        "keyword_count":     ("Keyword Count",       "Phishing keywords found in URL"),
        "has_at_symbol":     ("Has @ Symbol",        "@ in URL redirects to different host"),
        "has_double_slash":  ("Has Double Slash",    "// in path — redirection trick"),
        "domain_entropy":    ("Domain Entropy",      "Randomness of domain string (high = suspicious)"),
        "path_length":       ("Path Length",         "Character count of URL path"),
        "has_port":          ("Has Port",            "Non-standard port specified in URL"),
        "subdomain_count":   ("Subdomain Count",     "Number of subdomain levels"),
        "digit_ratio":       ("Digit Ratio",         "Ratio of digits in domain name"),
    }

    def is_valid_url(u: str) -> bool:
        """Returns True only if input looks like a real URL or domain."""
        import re
        u = u.strip()
        # Must have a dot and a valid TLD-like ending
        # Accept: http(s)://... or www.... or domain.tld patterns
        pattern = re.compile(
            r'^(https?://)'
            r'([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'
            r'(/[^\s]*)?$'
            r'|^(www\.)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(/[^\s]*)?$'
        )
        return bool(pattern.match(u)) and len(u) >= 4

    # ── Single URL instant analysis ──────────────────────────────────────────
    single_url = st.text_input(
        "Enter a URL",
        placeholder="https://www.google.com  or  http://paypa1-secure.xyz/login",
        key="single_url_input"
    )

    if single_url.strip() and not is_valid_url(single_url.strip()):
        st.error("Invalid input. Please enter a valid URL or domain (e.g. https://example.com)")
        st.stop()

    if single_url.strip() and is_valid_url(single_url.strip()):
        result = analyze_url(single_url.strip())
        badge_key = "high_risk" if result["label"] == "malicious" else result["label"]

        st.divider()
        col_left, col_right = st.columns([3, 1])

        with col_left:
            st.markdown(f"**URL:** `{result['url']}`")
            st.markdown(
                f"{risk_badge(badge_key)} &nbsp; Risk Score: **{result['risk_score']}/100**",
                unsafe_allow_html=True
            )
            st.divider()
            st.subheader("Feature Breakdown")

            rows = []
            for key, (label, description) in FEATURE_LABELS.items():
                val = result.get(key, 0)
                # Determine if this feature is a risk signal
                is_risk = (
                    (key == "has_ip" and val) or
                    (key == "suspicious_tld" and val) or
                    (key == "has_at_symbol" and val) or
                    (key == "has_double_slash" and val) or
                    (key == "has_port" and val) or
                    (key == "keyword_count" and val > 0) or
                    (key == "is_trusted_domain" and not val) or
                    (key == "domain_entropy" and val > 3.5) or
                    (key == "digit_ratio" and val > 0.3) or
                    (key == "num_subdomains" and val > 2)
                )
                is_good = (
                    (key == "is_https" and val) or
                    (key == "is_trusted_domain" and val)
                )
                flag = "🔴" if is_risk else ("🟢" if is_good else "⚪")
                rows.append({
                    "Status": flag,
                    "Feature": label,
                    "Value": val,
                    "Description": description
                })

            feat_df = pd.DataFrame(rows)
            st.dataframe(
                feat_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Status": st.column_config.TextColumn(width="small"),
                    "Feature": st.column_config.TextColumn(width="medium"),
                    "Value": st.column_config.NumberColumn(width="small"),
                    "Description": st.column_config.TextColumn(width="large"),
                }
            )

        with col_right:
            st.plotly_chart(
                score_gauge(result["risk_score"], "URL Risk Score"),
                use_container_width=True,
                key="single_url_gauge"
            )
            if result.get("blacklisted"):
                st.error(f"🚫 BLACKLISTED — {result.get('blacklist_reason', 'illegal/piracy site')}")
            elif result["label"] == "malicious":
                st.error("🚨 MALICIOUS — Do not visit this URL")
            elif result["label"] == "suspicious":
                st.warning("⚠️ SUSPICIOUS — Proceed with caution")
            else:
                st.success("✅ SAFE — URL appears legitimate")

    st.divider()

    # ── Batch URL analysis ────────────────────────────────────────────────────
    st.subheader("Batch URL Analysis")
    url_input = st.text_area(
        "Enter multiple URLs (one per line)",
        height=100,
        placeholder="http://suspicious-bank-login.xyz/verify\nhttps://www.google.com"
    )

    if st.button("🔍 Analyze All URLs", use_container_width=True):
        urls = [u.strip() for u in url_input.strip().split("\n") if u.strip()]
        valid_urls = [u for u in urls if is_valid_url(u)]
        invalid = [u for u in urls if not is_valid_url(u)]
        if invalid:
            st.warning(f"Skipped {len(invalid)} invalid entries: {', '.join(invalid[:3])}")
        if valid_urls:
            with st.spinner("Analyzing URLs..."):
                url_df = analyze_urls_batch(valid_urls)

            # Summary table
            summary_df = url_df[["url", "label", "risk_score", "is_https",
                                  "suspicious_tld", "keyword_count", "has_ip",
                                  "is_trusted_domain", "domain_entropy"]].copy()
            summary_df.columns = ["URL", "Label", "Risk Score", "HTTPS",
                                   "Suspicious TLD", "Keywords", "Has IP",
                                   "Trusted Domain", "Entropy"]
            st.dataframe(summary_df, use_container_width=True, hide_index=True)

            # Comparison chart
            url_df["short_url"] = url_df["url"].apply(lambda u: u[:45] + "..." if len(u) > 45 else u)
            fig = px.bar(
                url_df, x="short_url", y="risk_score", color="label",
                color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "malicious": "#e74c3c"},
                labels={"risk_score": "Risk Score", "short_url": "URL"},
                hover_data={"url": True, "short_url": False}
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                plot_bgcolor="rgba(0,0,0,0)", xaxis_tickangle=0
            )
            st.plotly_chart(fig, use_container_width=True, key="url_comparison_chart")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📊 Analytics":
    st.title("📊 Threat Analytics")

    if not results:
        st.info("👈 Load sample emails first from the sidebar.")
        st.stop()

    df = pd.DataFrame([{
        "risk_level": r["risk_report"]["risk_level"],
        "final_score": r["risk_report"]["final_score"],
        "nlp_score": r["risk_report"]["nlp_score"],
        "url_risk_score": r["risk_report"]["url_risk_score"],
        "anomaly_score": r["risk_report"]["anomaly_score"],
        "language": r["language"],
        "sender": r["sender"],
        "timestamp": r["timestamp"],
        "keyword_hits": r["text_features"].get("keyword_hits", 0),
        "urgency_score": r["text_features"].get("urgency_score", 0),
    } for r in results])

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Score Components by Risk Level")
        score_melt = df.melt(
            id_vars=["risk_level"],
            value_vars=["nlp_score", "url_risk_score", "anomaly_score"],
            var_name="Score Type", value_name="Score"
        )
        fig = px.box(score_melt, x="risk_level", y="Score", color="Score Type",
                     color_discrete_sequence=px.colors.qualitative.Set2)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                          plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True, key="analytics_box")

    with col2:
        st.subheader("Language-Based Attack Distribution")
        lang_risk = df.groupby(["language", "risk_level"]).size().reset_index(name="count")
        fig2 = px.bar(lang_risk, x="language", y="count", color="risk_level",
                      color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"},
                      barmode="stack")
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                           plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig2, use_container_width=True, key="analytics_lang")

    st.subheader("Risk Heatmap — Score Components")
    heatmap_df = df[["nlp_score", "url_risk_score", "anomaly_score", "final_score"]].T
    heatmap_df.columns = [f"Email {i+1}" for i in range(len(df))]
    fig3 = px.imshow(
        heatmap_df, color_continuous_scale="RdYlGn_r",
        labels={"color": "Score"}, aspect="auto"
    )
    fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=300)
    st.plotly_chart(fig3, use_container_width=True, key="analytics_heatmap")

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Keyword Hit Frequency")
        fig4 = px.histogram(df, x="keyword_hits", color="risk_level",
                            color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"})
        fig4.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                           plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig4, use_container_width=True, key="analytics_kw")

    with col4:
        st.subheader("Urgency Score Distribution")
        fig5 = px.scatter(df, x="urgency_score", y="final_score", color="risk_level",
                          size="keyword_hits",
                          color_discrete_map={"safe": "#2ecc71", "suspicious": "#f39c12", "high_risk": "#e74c3c"})
        fig5.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                           plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig5, use_container_width=True, key="analytics_urgency")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: MODEL INFO
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🤖 Model Info":
    st.title("🤖 Model Performance & Architecture")

    st.subheader("NLP Model Evaluation")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Accuracy", f"{model_report['accuracy']:.2%}")
    col2.metric("Precision (Phishing)", f"{model_report['phishing']['precision']:.2%}")
    col3.metric("Recall (Phishing)", f"{model_report['phishing']['recall']:.2%}")
    col4.metric("F1 Score (Phishing)", f"{model_report['phishing']['f1-score']:.2%}")

    st.subheader("Confusion Matrix")
    cm_df = pd.DataFrame(
        cm, index=["Actual Safe", "Actual Phishing"],
        columns=["Predicted Safe", "Predicted Phishing"]
    )
    fig_cm = px.imshow(cm_df, text_auto=True, color_continuous_scale="Blues",
                       labels={"color": "Count"})
    fig_cm.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=300)
    st.plotly_chart(fig_cm, use_container_width=True, key="confusion_matrix")

    st.subheader("System Architecture")
    st.markdown("""
    ```
    Email Input
        │
        ├─► Text Preprocessing (language detection, cleaning)
        │
        ├─► NLP Engine (TF-IDF + Random Forest)
        │       └─► Phishing probability score
        │
        ├─► URL Analyzer (feature extraction + rule-based scoring)
        │       └─► URL risk score per URL
        │
        ├─► Behavioral Anomaly Detector (Isolation Forest)
        │       └─► Sender anomaly score + flags
        │
        ├─► Risk Scorer (weighted combination)
        │       └─► Final score 0–100 + risk level
        │
        └─► Explainability Engine
                └─► Human-readable explanation + contributing factors
    ```
    """)

    st.subheader("Scoring Weights")
    from risk_scoring.scorer import WEIGHTS
    weights_df = pd.DataFrame([
        {"Module": k.replace("_", " ").title(), "Weight": f"{v*100:.0f}%"}
        for k, v in WEIGHTS.items()
    ])
    st.dataframe(weights_df, use_container_width=True)

    st.subheader("Supported Languages")
    st.markdown("""
    | Language | Script | Example Phishing Pattern |
    |----------|--------|--------------------------|
    | English | Latin | "Your account will be suspended" |
    | Hindi | Devanagari | "खाता बंद हो जाएगा" |
    | Hinglish | Mixed | "OTP share karo, account band hone wala hai" |
    | Tamil | Tamil | "உங்கள் கணக்கு நிறுத்தப்படும்" |
    | Telugu | Telugu | "మీ ఖాతా నిలిపివేయబడుతుంది" |
    """)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📄 Reports":
    st.title("📄 Security Report Export")

    if not results:
        st.info("👈 Load sample emails first from the sidebar.")
        st.stop()

    report_data = []
    for r in results:
        rr = r["risk_report"]
        report_data.append({
            "Email ID": r["email_id"],
            "Sender": r["sender"],
            "Subject": r["subject"],
            "Timestamp": r["timestamp"],
            "Language": r["language"],
            "Risk Level": rr["risk_level"],
            "Final Score": rr["final_score"],
            "NLP Score": rr["nlp_score"],
            "URL Risk Score": rr["url_risk_score"],
            "Anomaly Score": rr["anomaly_score"],
            "Domain Score": rr["domain_reputation_score"],
            "Explanation": r["explanation"]["summary"],
            "Recommended Action": rr["recommended_action"],
            "Flags": " | ".join(rr["flags"]),
        })

    report_df = pd.DataFrame(report_data)
    st.dataframe(report_df, use_container_width=True)

    csv = report_df.to_csv(index=False)
    st.download_button(
        "⬇️ Download CSV Report",
        data=csv,
        file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True
    )

    json_report = json.dumps([r["risk_report"] for r in results], indent=2)
    st.download_button(
        "⬇️ Download JSON Report",
        data=json_report,
        file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True
    )
