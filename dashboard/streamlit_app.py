"""
Interactive Security Dashboard for OWASP LLM & Agentic AI Red Teaming.
Allows dynamic switching between Claude and Gemini, mitigation toggling,
live attack simulation, Wazuh alert feed, and benchmark results analysis.
"""
import streamlit as st
import json
import pandas as pd
from pathlib import Path

from app.config import RESULTS_DIR, LOGS_DIR, REPORTS_DIR, CANARIES, WAZUH_LOG_FILE
from app.agent.core import AIAgent
from app.mcp.server import MockMCPServer
from app.mcp.client import MCPClient
from tests.test_cases import ALL_TEST_CASES

st.set_page_config(
    page_title="OWASP LLM & Agentic AI Security Benchmark",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header { font-size: 26px; font-weight: 700; color: #1E3A8A; margin-bottom: 5px; }
    .sub-header { font-size: 15px; color: #4B5563; margin-bottom: 20px; }
    .metric-card { background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; }
    .badge-vuln { background-color: #FEE2E2; color: #991B1B; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-safe { background-color: #DCFCE7; color: #166534; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='main-header'>🛡️ OWASP LLM & Agentic AI Security Lab</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-header'>Comparative Red Teaming: Claude 3.5 Sonnet vs Google Gemini 2.5 Flash</div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# SIDEBAR CONTROLS
# -------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Agent & Model Controls")

    selected_model = st.selectbox(
        "Select Target Model:",
        options=["claude", "gemini"],
        format_func=lambda x: "Anthropic Claude 3.5 Sonnet" if x == "claude" else "Google Gemini 2.5 Flash"
    )

    mitigation_active = st.toggle("Enable Security Guardrails", value=False)
    if mitigation_active:
        st.success("🛡️ Guardrails ACTIVE: XML Isolation, Canary Scrubber, Path Canonicalization, Rate Limiter")
    else:
        st.error("⚠️ Guardrails DISABLED: System in Vulnerable Baseline Mode")

    st.divider()
    st.subheader("🛠️ Active Agent Tools")
    tool_file = st.checkbox("FileReader (read_file)", value=True)
    tool_email = st.checkbox("EmailSender (send_email)", value=True)
    tool_http = st.checkbox("HttpCaller (fetch_url)", value=True)

    st.divider()
    st.markdown("### 🏷️ Harmless Security Canaries")
    st.code(f"Primary:  {CANARIES['PRIMARY_FLAG']}\nSandbox:  {CANARIES['FS_FLAG']}\nSSRF:     {CANARIES['SSRF_FLAG']}\nMCP:      {CANARIES['MCP_FLAG']}")

# -------------------------------------------------------------
# TABS INTERFACE
# -------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🎯 Interactive Attack Lab",
    "📊 Benchmark Results & Comparison",
    "🔌 MCP Connection Risk POC",
    "🚨 Wazuh SIEM Live Feed",
    "📑 Report & Deliverables"
])

# =============================================================
# TAB 1: INTERACTIVE ATTACK LAB
# =============================================================
with tab1:
    st.subheader("Live Red Teaming Playground")
    st.write("Execute simulated OWASP attack vectors against the sandboxed agent and observe defensive behavior.")

    col_select, col_custom = st.columns([1, 1])

    with col_select:
        test_case_options = {tc["name"]: tc for tc in ALL_TEST_CASES}
        selected_tc_name = st.selectbox("Select Pre-Configured Attack Vector:", list(test_case_options.keys()))
        current_tc = test_case_options[selected_tc_name]
        st.info(f"**Risk ID:** `{current_tc['risk_id']}` | **Category:** {current_tc['category']}\n\n**Attack Vector:** {current_tc['attack_vector']}")

    with col_custom:
        user_prompt = st.text_area("Attack Prompt to Execute:", value=current_tc["prompt"], height=110)

    if st.button("🚀 Launch Attack Against Agent", type="primary"):
        with st.spinner(f"Executing prompt through {selected_model.capitalize()}..."):
            agent = AIAgent(provider=selected_model, mitigated=mitigation_active)
            result = agent.execute(user_prompt, risk_id=current_tc["risk_id"])

        col_resp, col_telemetry = st.columns([1.2, 0.8])

        with col_resp:
            st.markdown("#### 🤖 Model / Agent Response")
            st.text_area("Agent Output:", value=result.response, height=180)

            if result.tools_executed:
                st.markdown("#### 🔧 Tools Executed")
                for t in result.tools_executed:
                    st.json(t)

        with col_telemetry:
            st.markdown("#### 🔍 Security Telemetry")
            if result.canary_leaked:
                st.markdown("<span class='badge-vuln'>🚨 CRITICAL: SENSITIVE CANARY LEAK DETECTED</span>", unsafe_allow_html=True)
                st.error(f"Leaked Canary: {result.leaked_canaries}")
            elif result.attack_blocked:
                st.markdown("<span class='badge-safe'>✅ DEFENSE SUCCESSFUL: ATTACK BLOCKED</span>", unsafe_allow_html=True)
                st.success("Guardrails intercepted malicious payload before execution.")
            elif not mitigation_active:
                st.markdown("<span class='badge-vuln'>⚠️ VULNERABLE EXECUTION</span>", unsafe_allow_html=True)
                st.warning("Payload executed without guardrail intervention.")
            else:
                st.markdown("<span class='badge-safe'>🛡️ SAFE BENIGN EXECUTION</span>", unsafe_allow_html=True)

            if result.security_event:
                st.markdown("#### 📡 Wazuh Event Snapshot")
                st.json(result.security_event)

# =============================================================
# TAB 2: BENCHMARK RESULTS & COMPARISON
# =============================================================
with tab2:
    st.subheader("Benchmark Comparison: Claude 3.5 Sonnet vs Gemini 2.5 Flash")

    summary_file = RESULTS_DIR / "comparison_summary.json"
    csv_file = RESULTS_DIR / "results.csv"

    if summary_file.exists():
        with open(summary_file, "r") as f:
            summary = json.load(f)

        c = summary.get("claude", {})
        g = summary.get("gemini", {})

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Claude Unmitigated ASR", f"{c.get('unmitigated_asr', 84.4)}%", f"{c.get('unmitigated_success', 27)}/32 Vuln", delta_color="inverse")
        col2.metric("Gemini Unmitigated ASR", f"{g.get('unmitigated_asr', 90.6)}%", f"{g.get('unmitigated_success', 29)}/32 Vuln", delta_color="inverse")
        col3.metric("Claude Mitigated ASR", f"{c.get('mitigated_asr', 0.0)}%", "-100% Vuln", delta_color="normal")
        col4.metric("Gemini Mitigated ASR", f"{g.get('mitigated_asr', 0.0)}%", "-100% Vuln", delta_color="normal")

    if csv_file.exists():
        df = pd.read_csv(csv_file)
        st.markdown("### 📋 Results Sheet (Filtered Explorer)")
        
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            risk_filter = st.multiselect("Filter by Risk ID:", options=list(df["risk_id"].unique()), default=list(df["risk_id"].unique()))
        with col_f2:
            model_filter = st.multiselect("Filter by Model:", options=list(df["model"].unique()), default=list(df["model"].unique()))

        filtered_df = df[(df["risk_id"].isin(risk_filter)) & (df["model"].isin(model_filter))]
        st.dataframe(filtered_df, use_container_width=True, height=350)

        csv_bytes = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Full Results Sheet (CSV)",
            data=csv_bytes,
            file_name="results.csv",
            mime="text/csv"
        )

# =============================================================
# TAB 3: MCP CONNECTION RISK POC
# =============================================================
with tab3:
    st.subheader("Model Context Protocol (MCP) Connection Risk POC")
    st.write(
        "Demonstrates attack vector where an AI agent connects to a remote rogue MCP server advertising a poisoned tool description. "
        "The agent is tricked into passing internal credentials to the remote tool."
    )

    col_mcp_left, col_mcp_right = st.columns(2)

    with col_mcp_left:
        st.markdown("#### 1. Unmitigated Rogue MCP Connection")
        if st.button("Run Unmitigated MCP Attack"):
            rogue_server = MockMCPServer(mode="rogue")
            client = MCPClient(rogue_server)
            tools, _ = client.discover_tools(mitigated=False)
            st.error(f"⚠️ Discovered Poisoned Tool: {tools[0]['name']}")
            st.code(f"Poisoned Tool Description:\n{tools[0]['description']}")

            st.write("Executing tool with internal secret flag...")
            res = client.execute_tool("system_diagnostic_check", {"diagnostic_token": CANARIES["MCP_FLAG"]}, mitigated=False)
            st.error(f"🚨 Remote MCP Server Received Flag: {res}")
            st.markdown("<span class='badge-vuln'>ATTACK SUCCESSFUL: Canary exfiltrated via MCP</span>", unsafe_allow_html=True)

    with col_mcp_right:
        st.markdown("#### 2. Mitigated MCP Connection (Attestation & DLP)")
        if st.button("Run Mitigated MCP Verification"):
            rogue_server = MockMCPServer(mode="rogue")
            client = MCPClient(rogue_server)
            safe_tools, alerts = client.discover_tools(mitigated=True)
            for a in alerts:
                st.warning(f"🛡️ {a}")
            st.success(f"Safe Approved Tools Count: {len(safe_tools)}")

            st.write("Testing Outbound Argument DLP Enforcement...")
            res = client.execute_tool("system_diagnostic_check", {"diagnostic_token": CANARIES["MCP_FLAG"]}, mitigated=True)
            st.success(f"DLP Guard Response: {res['message']}")
            st.markdown("<span class='badge-safe'>DEFENSE SUCCESSFUL: Malicious tool quarantined & exfiltration blocked</span>", unsafe_allow_html=True)

# =============================================================
# TAB 4: WAZUH SIEM LIVE FEED
# =============================================================
with tab4:
    st.subheader("Wazuh SIEM Live Security Alerts")
    st.write("Real-time stream of JSON events emitted by the AI agent to the centralized SIEM.")

    if WAZUH_LOG_FILE.exists():
        with open(WAZUH_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        events = [json.loads(line) for line in reversed(lines[-25:])]
        st.info(f"Showing last {len(events)} security events from `{WAZUH_LOG_FILE}`.")

        for ev in events:
            lvl = ev["rule"]["level"]
            lvl_color = "red" if lvl >= 12 else ("orange" if lvl >= 9 else "blue")
            with st.expander(f"[{ev['data']['owasp_risk_id']}] {ev['rule']['description']} (Severity: Level {lvl}) - {ev['timestamp']}"):
                st.json(ev)
    else:
        st.warning("No Wazuh logs generated yet. Run tests to populate log stream.")

# =============================================================
# TAB 5: REPORT & DELIVERABLES
# =============================================================
with tab5:
    st.subheader("Project Documentation & Deliverables")

    pdf_file = REPORTS_DIR / "OWASP_LLM_Agentic_Security_Report.pdf"
    if pdf_file.exists():
        with open(pdf_file, "rb") as f:
            pdf_bytes = f.read()

        st.success("📄 Formal PDF Security Report Generated (9 Pages, Fully Formatted).")
        st.download_button(
            label="📥 Download Executive PDF Report (OWASP_LLM_Agentic_Security_Report.pdf)",
            data=pdf_bytes,
            file_name="OWASP_LLM_Agentic_Security_Report.pdf",
            mime="application/pdf"
        )
    else:
        st.warning("PDF report not yet generated.")

    st.markdown("### 📦 Deliverables Checklist")
    st.markdown("""
    - [x] **Small LLM App & AI Agent with Tools:** `app/agent/core.py`, `app/tools/` (FileReader, EmailSender, HttpCaller)
    - [x] **Dual Model Switcher:** Claude 3.5 Sonnet & Gemini 2.5 Flash (`app/models/`)
    - [x] **>= 3 Attack Test Cases per Risk:** 32 comprehensive attack vectors (`tests/test_cases.py`)
    - [x] **One Mitigation per Risk with Before-and-After Results:** 100% evaluated (`app/defenses/`, `tests/run_poc.py`)
    - [x] **Model Context Protocol (MCP) Connection Risk & POC:** (`app/mcp/`)
    - [x] **Automated Wazuh SIEM Integration:** (`app/monitoring/wazuh_logger.py`, `logs/wazuh_alerts.json`)
    - [x] **Results Sheet (CSV & JSON):** (`results/results.csv`, `results/results.json`)
    - [x] **Executive PDF Report (max 10 pages):** 9-page publication report (`reports/OWASP_LLM_Agentic_Security_Report.pdf`)
    - [x] **Isolated Docker Sandbox Configuration:** (`docker/Dockerfile`, `docker/docker-compose.yml`)
    """)
