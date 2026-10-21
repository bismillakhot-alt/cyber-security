import streamlit as st
import pandas as pd
import plotly.express as px

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS (dark theme) ───────────────────────────────────────────────────
st.markdown("""
<style>
    /* Overall background */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }

    /* Header area */
    .cyber-header {
        text-align: center;
        padding: 2rem 0 1rem 0;
    }
    .cyber-title {
        font-size: 2.8rem;
        font-weight: 700;
        color: #58a6ff;
        letter-spacing: 3px;
    }
    .cyber-subtitle {
        font-size: 1rem;
        color: #8b949e;
        margin-top: 0.4rem;
    }

    /* Metric cards */
    .card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        text-align: center;
    }
    .card-label {
        font-size: 0.85rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 0.5rem;
    }
    .card-value {
        font-size: 2.4rem;
        font-weight: 700;
    }
    .blue  { color: #58a6ff; }
    .green { color: #3fb950; }
    .red   { color: #f85149; }
    .orange{ color: #d29922; }

    /* Divider */
    hr { border-color: #21262d; }

    /* Section heading */
    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #58a6ff;
        margin: 1.8rem 0 0.6rem 0;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-header">
    <div class="cyber-title">🛡️ CYBERSHIELD</div>
    <div class="cyber-subtitle">
        Real-time Security Monitoring Dashboard &nbsp;|&nbsp; Protect. Detect. Respond.
    </div>
</div>
<hr>
""", unsafe_allow_html=True)

# ── 20 fake login records ─────────────────────────────────────────────────────
# NOTE: 192.168.4.77 appears 5 times with "Failed" — suspicious attacker IP
SAMPLE_RECORDS = [
    {"Time": "2024-06-10 08:01:14", "Username": "alice",    "IP Address": "10.0.0.12",     "Result": "Success"},
    {"Time": "2024-06-10 08:03:52", "Username": "bob",      "IP Address": "10.0.0.45",     "Result": "Success"},
    {"Time": "2024-06-10 08:07:33", "Username": "carol",    "IP Address": "172.16.0.5",    "Result": "Success"},
    {"Time": "2024-06-10 08:11:09", "Username": "admin",    "IP Address": "192.168.4.77",  "Result": "Failed"},   # suspicious
    {"Time": "2024-06-10 08:11:44", "Username": "admin",    "IP Address": "192.168.4.77",  "Result": "Failed"},   # suspicious
    {"Time": "2024-06-10 08:12:01", "Username": "root",     "IP Address": "192.168.4.77",  "Result": "Failed"},   # suspicious
    {"Time": "2024-06-10 08:12:19", "Username": "root",     "IP Address": "192.168.4.77",  "Result": "Failed"},   # suspicious
    {"Time": "2024-06-10 08:12:38", "Username": "sysadmin", "IP Address": "192.168.4.77",  "Result": "Failed"},   # suspicious
    {"Time": "2024-06-10 08:15:22", "Username": "david",    "IP Address": "10.0.0.88",     "Result": "Success"},
    {"Time": "2024-06-10 08:19:47", "Username": "emma",     "IP Address": "10.0.1.3",      "Result": "Success"},
    {"Time": "2024-06-10 08:23:05", "Username": "frank",    "IP Address": "172.16.0.22",   "Result": "Failed"},
    {"Time": "2024-06-10 08:27:31", "Username": "grace",    "IP Address": "10.0.0.67",     "Result": "Success"},
    {"Time": "2024-06-10 08:31:14", "Username": "henry",    "IP Address": "10.0.2.9",      "Result": "Success"},
    {"Time": "2024-06-10 08:35:58", "Username": "irene",    "IP Address": "172.16.1.14",   "Result": "Success"},
    {"Time": "2024-06-10 08:40:02", "Username": "jack",     "IP Address": "10.0.0.31",     "Result": "Failed"},
    {"Time": "2024-06-10 08:44:19", "Username": "karen",    "IP Address": "10.0.3.50",     "Result": "Success"},
    {"Time": "2024-06-10 08:48:33", "Username": "leo",      "IP Address": "172.16.0.8",    "Result": "Success"},
    {"Time": "2024-06-10 08:52:11", "Username": "mia",      "IP Address": "10.0.1.77",     "Result": "Success"},
    {"Time": "2024-06-10 08:56:44", "Username": "noah",     "IP Address": "10.0.0.19",     "Result": "Success"},
    {"Time": "2024-06-10 09:01:07", "Username": "olivia",   "IP Address": "172.16.2.3",    "Result": "Success"},
]

# ── Build DataFrame ───────────────────────────────────────────────────────────
df_all = pd.DataFrame(SAMPLE_RECORDS)

# ── DETECTION RULE: flag IPs with 5 or more failed logins ────────────────────
#
#   Step 1 – keep only the rows where the login Result is "Failed"
#   Step 2 – count how many times each IP Address appears in those rows
#   Step 3 – loop through the counts with a simple if statement:
#             if the count is 5 or more → that IP is suspicious
#
# No machine learning, no external service — just counting and comparing.

SUSPICIOUS_THRESHOLD = 5   # change this number to make the rule stricter/looser

# Step 1 & 2: count failed attempts per IP
failed_rows   = df_all[df_all["Result"] == "Failed"]          # filter to failed rows only
failed_counts = failed_rows.groupby("IP Address").size()      # e.g. {"192.168.4.77": 5, ...}

# Step 3: apply the rule with a plain if statement
suspicious_ips = []   # will hold every IP that broke the rule

for ip_address, fail_count in failed_counts.items():
    if fail_count >= SUSPICIOUS_THRESHOLD:      # THE RULE: 5 or more failures = suspicious
        suspicious_ips.append(ip_address)       # flag this IP

# ── Assign a Risk Level to every row ─────────────────────────────────────────
#   High   → IP is in our suspicious list (≥5 failures)
#   Medium → login failed but IP is not suspicious
#   Low    → login succeeded
#
# We use a simple helper function with if/elif/else — no ML involved.

def assign_risk(row):
    if row["IP Address"] in suspicious_ips and row["Result"] == "Failed":
        return "High"       # brute-force pattern detected
    elif row["Result"] == "Failed":
        return "Medium"     # single failure — could just be a typo
    else:
        return "Low"        # successful login — no risk

df_all["Risk Level"] = df_all.apply(assign_risk, axis=1)

# ── Dashboard summary numbers ─────────────────────────────────────────────────
total_logins          = len(df_all)
successful_logins     = len(df_all[df_all["Result"] == "Success"])
failed_logins         = len(df_all[df_all["Result"] == "Failed"])
suspicious_activities = len(suspicious_ips)   # auto-updated by the rule above

# ── Four metric cards ─────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

cards = [
    (col1, "Total Logins",          total_logins,          "blue"),
    (col2, "Successful Logins",     successful_logins,     "green"),
    (col3, "Failed Logins",         failed_logins,         "orange"),
    (col4, "Suspicious Activities", suspicious_activities, "red"),
]

for col, label, value, color in cards:
    with col:
        st.markdown(f"""
        <div class="card">
            <div class="card-label">{label}</div>
            <div class="card-value {color}">{value:,}</div>
        </div>
        """, unsafe_allow_html=True)

# ── CHARTS ────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">📊 Login Analytics</div>', unsafe_allow_html=True)

chart_col1, chart_col2 = st.columns(2)

# ── Chart 1: Successful vs Failed Logins (bar chart) ─────────────────────────
# WHY IT HELPS: at a glance you can see the ratio of good vs bad logins.
# A sudden spike in the "Failed" bar is an early sign of an attack.
with chart_col1:
    st.markdown("**Login Outcome Comparison**")
    st.caption("Shows how many logins succeeded vs. failed. "
               "A high Failed bar is an early warning sign.")

    # Count how many rows have each Result value → e.g. Success: 15, Failed: 5
    outcome_counts = df_all["Result"].value_counts().reset_index()
    outcome_counts.columns = ["Result", "Count"]

    fig1 = px.bar(
        outcome_counts,
        x="Result",
        y="Count",
        color="Result",
        color_discrete_map={"Success": "#3fb950", "Failed": "#f85149"},
        text="Count",               # show the number on top of each bar
    )
    fig1.update_layout(
        plot_bgcolor="#161b22",
        paper_bgcolor="#161b22",
        font_color="#c9d1d9",
        showlegend=False,
        margin=dict(t=20, b=20, l=10, r=10),
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="#21262d"),
    )
    fig1.update_traces(textposition="outside")
    st.plotly_chart(fig1, use_container_width=True)

# ── Chart 2: Failed Login Attempts by IP Address (bar chart) ─────────────────
# WHY IT HELPS: makes it immediately obvious which IP is causing the most
# failures. A bar that stands much taller than others = likely attacker.
with chart_col2:
    st.markdown("**Failed Attempts by IP Address**")
    st.caption("Each bar is one IP address. A very tall bar means that IP "
               "failed many times — the rule flags it as suspicious at 5+.")

    # We already have failed_counts (Series: IP → count of failures)
    failed_df = failed_counts.reset_index()
    failed_df.columns = ["IP Address", "Failed Attempts"]

    # Colour bars: red if the IP is suspicious, orange otherwise
    failed_df["Color"] = failed_df["IP Address"].apply(
        lambda ip: "#f85149" if ip in suspicious_ips else "#d29922"
    )

    fig2 = px.bar(
        failed_df,
        x="IP Address",
        y="Failed Attempts",
        color="Color",              # use our custom colour column
        color_discrete_map="identity",  # tell Plotly the column holds actual colours
        text="Failed Attempts",
    )
    fig2.update_layout(
        plot_bgcolor="#161b22",
        paper_bgcolor="#161b22",
        font_color="#c9d1d9",
        showlegend=False,
        margin=dict(t=20, b=20, l=10, r=10),
        xaxis=dict(showgrid=False, tickangle=-20),
        yaxis=dict(showgrid=True, gridcolor="#21262d", dtick=1),
    )
    fig2.update_traces(textposition="outside")
    st.plotly_chart(fig2, use_container_width=True)

# ── FILTERS + TABLE ───────────────────────────────────────────────────────────
st.markdown('<div class="section-title">📋 Login Records</div>', unsafe_allow_html=True)

# Two side-by-side filter dropdowns
filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    # Filter by login result (Success / Failed / All)
    # Selecting "All" means no filter is applied — every row is shown.
    result_filter = st.selectbox(
        "🔍 Filter by Login Result",
        options=["All", "Success", "Failed"],
    )

with filter_col2:
    # Filter by risk level (Low / Medium / High / All)
    # Risk Level was assigned automatically by the detection rule above.
    risk_filter = st.selectbox(
        "⚠️ Filter by Risk Level",
        options=["All", "Low", "Medium", "High"],
    )

# Apply the filters using plain if statements
# Start with the full dataset, then narrow it down step by step.
df_filtered = df_all.copy()

if result_filter != "All":
    # Keep only rows where the Result column matches the chosen value
    df_filtered = df_filtered[df_filtered["Result"] == result_filter]

if risk_filter != "All":
    # Keep only rows where the Risk Level column matches the chosen value
    df_filtered = df_filtered[df_filtered["Risk Level"] == risk_filter]

# Button toggles the table in session state
if "show_table" not in st.session_state:
    st.session_state.show_table = False

if st.button("🔄 Generate Sample Data"):
    st.session_state.show_table = True

if st.session_state.show_table:

    # ── Suspicious IP warning banners ─────────────────────────────────────────
    if suspicious_ips:
        st.markdown('<div class="section-title">🚨 Suspicious Activity Detected</div>',
                    unsafe_allow_html=True)

        for ip in suspicious_ips:
            count = int(failed_counts[ip])
            usernames_tried = df_all[
                (df_all["IP Address"] == ip) & (df_all["Result"] == "Failed")
            ]["Username"].unique()
            usernames_str = ", ".join(usernames_tried)

            st.warning(
                f"⚠️  **Suspicious IP detected: `{ip}`**\n\n"
                f"- **Rule triggered:** {count} failed login attempts "
                f"(threshold = {SUSPICIOUS_THRESHOLD})\n"
                f"- **Usernames attempted:** {usernames_str}\n"
                f"- **Why this is suspicious:** A normal user forgets their password "
                f"once or twice. Trying {count} times across different usernames "
                f"in under 2 minutes is a sign of an automated brute-force attack.\n"
                f"- **Recommended action:** Block IP `{ip}` at the firewall."
            )

    # ── Show filtered row count ────────────────────────────────────────────────
    st.caption(f"Showing {len(df_filtered)} of {len(df_all)} records  "
               f"(Result: **{result_filter}** | Risk: **{risk_filter}**)")

    # ── Colour-code the filtered table rows ───────────────────────────────────
    def highlight_result(row):
        if row["Risk Level"] == "High":
            return ["background-color: #3d1414; color: #f85149"] * len(row)
        elif row["Risk Level"] == "Medium":
            return ["background-color: #2d1e00; color: #d29922"] * len(row)
        else:
            return ["color: #3fb950"] * len(row)

    styled_df = df_filtered.style.apply(highlight_result, axis=1)
    st.dataframe(styled_df, use_container_width=True, hide_index=True)

    # Legend
    st.markdown("""
    <small style="color:#8b949e;">
    🟢 Green = Low risk (successful login) &nbsp;|&nbsp;
    🟠 Orange = Medium risk (single failure) &nbsp;|&nbsp;
    🔴 Red = High risk (suspicious IP with ≥5 failures)
    </small>
    """, unsafe_allow_html=True)
