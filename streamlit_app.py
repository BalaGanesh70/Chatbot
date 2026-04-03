import os
import requests
import streamlit as st
import time
import pandas as pd
import plotly.express as px


API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")


st.set_page_config(page_title="Organization Chatbot", page_icon="🔒", layout="wide")

if "auth" not in st.session_state:
    st.session_state.auth = {"logged_in": False, "name": None, "role": None}

auth = st.session_state.auth

if "session_id" not in st.session_state:
    import uuid
    st.session_state.session_id = uuid.uuid4().hex[:32]

if "view" not in st.session_state:
    st.session_state.view = "login"

if "locally_blocked" not in st.session_state:
    st.session_state.locally_blocked = False


def get_block_status():
    try:
        current_role = (st.session_state.auth or {}).get("role")
        r = requests.get(
            f"{API_URL}/block-status",
            params={"session_id": st.session_state.session_id, "role": current_role},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return bool(data.get("blocked", False)), int(data.get("remaining", 0))
    except Exception:
        pass
    return False, 0

def show_register():
    st.title("Create an account")
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        main_id_password = st.text_input("Main ID Password", type="password")
        role = st.selectbox(
            "Role",
            ["Visitor", "Applicant", "Intern", "Senior Engineer", "Tech Lead", "HR"],
            index=0,
        )
        date_of_birth = st.text_input("Date of Birth (YYYY-MM-DD)")
        government_id = st.text_input("Government ID")
        submitted = st.form_submit_button("Register")
        if submitted:
            if not username or not email or not main_id_password:
                st.error("Please fill in all required fields")
            else:
                try:
                    r = requests.post(
                        f"{API_URL}/register",
                        json={
                            "username": username,
                            "email": email,
                            "main_id_password": main_id_password,
                            "role": role,
                            "date_of_birth": date_of_birth,
                            "government_id": government_id,
                        },
                        timeout=20,
                    )
                    if r.status_code == 200:
                        st.success("Registration successful. Please log in.")
                        st.session_state.view = "login"
                    else:
                        try:
                            err = r.json().get("detail", r.text)
                        except Exception:
                            err = r.text
                        st.error(err)
                except Exception as e:
                    st.error(f"Failed to reach API: {e}")


def show_login():
    st.title("Log in")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password (Main ID Password)", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            try:
                r = requests.post(
                    f"{API_URL}/login",
                    json={"username": username, "password": password},
                    timeout=20,
                )
                if r.status_code == 200:
                    data = r.json()
                    auth.update({"logged_in": True, "name": data.get("name"), "role": data.get("role")})
                    st.session_state.view = "chat"
                    st.rerun()
                else:
                    try:
                        err = r.json().get("detail", r.text)
                    except Exception:
                        err = r.text
                    st.error(err)
            except Exception as e:
                st.error(f"Failed to reach API: {e}")


def show_chat_sidebar():
    with st.sidebar:
        st.write(f"Signed in as: {auth.get('name')} ({auth.get('role')})")
        if st.button("Chat History"):
            st.session_state.view = "history"
            st.rerun()
        if st.button("Log out"):
            st.session_state.auth = {"logged_in": False, "name": None, "role": None}
            st.session_state.view = "login"
            st.session_state.messages = []
            st.session_state.locally_blocked = False
            try:
                requests.delete(f"{API_URL}/data-leaks", params={"session_id": st.session_state.session_id}, timeout=10)
            except Exception:
                pass
            st.rerun()
        if (auth.get("role") == "HR"):
            if st.button("View Data Leaks"):
                st.session_state.view = "leaks"
                st.rerun()

        # Sticky Back to Chat button at the bottom of sidebar for non-chat views
        if st.session_state.get("view") in ("history", "leaks"):
            st.markdown(
                """
                <style>
                /* Pin the back button container to the bottom of the sidebar */
                div[data-testid="stSidebar"] .back-to-chat-container {
                    position: fixed;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    padding: 1rem;
                    background: inherit;
                    box-shadow: 0 -1px 0 0 rgba(0,0,0,0.05);
                }
                </style>
                """,
                unsafe_allow_html=True,
            )
            st.markdown('<div class="back-to-chat-container">', unsafe_allow_html=True)
            if st.button("Back to Chat", key="back_to_chat_sidebar"):
                st.session_state.view = "chat"
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)


def show_chat_header():
    st.title("Organization Chatbot")
    st.caption("Ask organization and hiring related questions. Other topics aren't available.")


def show_leaks_view():
    st.title("AI Security & Leak Detection Dashboard")
    st.markdown("---")
    
    # Fetch dashboard data
    try:
        # Get basic leaks data (session-based)
        r = requests.get(f"{API_URL}/data-leaks", params={"session_id": st.session_state.session_id}, timeout=20)
        if r.status_code != 200:
            st.error(f"Failed to load leaks: {r.status_code}")
            return
        
        leaks = r.json() or []
        total_leaks = len(leaks)
        
        # Get persistent security scan results from database
        scan_r = requests.get(f"{API_URL}/security-scan-results", timeout=20)
        if scan_r.status_code == 200:
            security_scan_data = scan_r.json()
        else:
            # Fallback to default values if API fails
            security_scan_data = {
                "fake_names_count": 0,
                "medical_records_count": 0,
                "api_keys_count": 0,
                "jailbreak_attempts_count": 0,
                "pii_phi_secrets_count": 0,
                "risky_flows_count": 0,
                "external_calls_count": 0,
                "resistance_percentage": 100,
                "leaked_records_count": 0
            }
        
        # Calculate session-based dashboard metrics
        session_dashboard_data = calculate_dashboard_metrics(leaks)
        
        # Top Section - Security Scan Results (Persistent from Database)
        st.header("Security Scan Results")
        st.caption("⚠️ These metrics persist across sessions and accumulate over time")
        
        # Add spacing between sections
        st.markdown("<br>", unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("### Seeding & Scanning for Fake Entities")
            st.markdown("<br>", unsafe_allow_html=True)
            st.metric(
                label="Fake Names",
                value=security_scan_data.get("medical_records_count", 0),
                delta="Detected"
            )
            st.markdown("<br>", unsafe_allow_html=True)
            # Intentionally left empty (API Keys removed from frontend display)
        
        with col2:
            st.markdown("### Jailbreak Prompt Battery")
            st.markdown("<br>", unsafe_allow_html=True)
            jailbreak_count = security_scan_data.get("jailbreak_attempts_count", 0)
            st.metric(
                label="Jailbreak Attempts",
                value=jailbreak_count,
                delta="Blocked" if jailbreak_count > 0 else "None"
            )
            
            if jailbreak_count > 0:
                st.warning(f"{jailbreak_count} jailbreak prompt(s) detected and blocked")
            else:
                st.success("No jailbreak attempts detected")
        
        with col3:
            st.markdown("### Monitor AI Behavior")
            st.markdown("<br>", unsafe_allow_html=True)
            st.metric(
                label="PII/PHI/Secrets",
                value=security_scan_data.get("pii_phi_secrets_count", 0),
                delta="Detected"
            )
            st.markdown("<br>", unsafe_allow_html=True)
            st.metric(
                label="Risky Flows",
                value=security_scan_data.get("risky_flows_count", 0),
                delta="Identified"
            )
        
        with col4:
            st.markdown("### Detect & Flag")
            st.markdown("<br>", unsafe_allow_html=True)
            if security_scan_data.get("leaked_records_count", 0) > 0:
                st.error("**LEAK DETECTED**")
                st.markdown("<br>", unsafe_allow_html=True)
                st.error("**Credentials Exposure Risk**")
                st.markdown("<br>", unsafe_allow_html=True)
                st.error("**Data Exposure Risk**")
            else:
                st.success("**No Leaks Detected**")
                st.info("**Low Risk**")
        
        st.markdown("---")
        
        # Bottom Section - Security Analysis & Recommendations (Session-based)
        st.header("Security Analysis & Recommendations")
        st.caption("⚠️ These metrics are session-based and reset on refresh/new session")
        st.markdown("<br>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Results")
            st.markdown("<br>", unsafe_allow_html=True)
            # Use session-based data for this section
            resistance_pct = session_dashboard_data.get("results", {}).get("resistance_percentage", 100)
            leaked_records = session_dashboard_data.get("results", {}).get("leaked_records", 0)
            
            st.metric(
                label="AI Resistance",
                value=f"{resistance_pct}%",
                delta="of attacks resisted"
            )
            st.markdown("<br>", unsafe_allow_html=True)
            st.metric(
                label="Leaked Records",
                value=leaked_records,
                delta="sensitive data exposed"
            )
            
            # Progress bar for resistance
            st.progress(resistance_pct / 100)
            st.caption(f"Your AI resisted {resistance_pct}% of our attacks")
        
        with col2:
            st.markdown("### Recommendations")
            st.markdown("<br>", unsafe_allow_html=True)
            recommendations = generate_security_recommendations(leaks, session_dashboard_data)
            if recommendations:
                for i, rec in enumerate(recommendations[:3], 1):
                    st.markdown(f"**{i}.** {rec}")
            else:
                st.info("No specific recommendations at this time")
        
        st.markdown("---")
        
        # Detailed Analytics Section (Session-based)
        if leaks:
            st.header("Detailed Security Analytics")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### Data Level Exposure Risk")
                st.markdown("<br>", unsafe_allow_html=True)
                # Calculate data exposure risk based on leak types and categories
                data_exposure_data = get_data_exposure_risk(leaks)
                if data_exposure_data:
                    df_data = pd.DataFrame(data_exposure_data)
                    fig_data = px.bar(
                        df_data,
                        x='risk_type',
                        y='count',
                        title="Data Exposure Risk by Type",
                        color='count',
                        color_continuous_scale='Reds'
                    )
                    st.plotly_chart(fig_data, use_container_width=True)
                else:
                    # Show session-based data instead of "No data available"
                    session_data_exposure = get_session_data_exposure_risk(leaks)
                    if session_data_exposure:
                        df_data = pd.DataFrame(session_data_exposure)
                        fig_data = px.bar(
                            df_data,
                            x='risk_type',
                            y='count',
                            title="Data Exposure Risk by Type (Session)",
                            color='count',
                            color_continuous_scale='Reds'
                        )
                        st.plotly_chart(fig_data, use_container_width=True)
                    else:
                        st.info("No data exposure risk data available for this session")
            
            with col2:
                st.markdown("### Credential Exposure Risk")
                st.markdown("<br>", unsafe_allow_html=True)
                # Calculate credential exposure risk
                credential_exposure_data = get_credential_exposure_risk(leaks)
                if credential_exposure_data:
                    df_cred = pd.DataFrame(credential_exposure_data)
                    fig_cred = px.pie(
                        df_cred,
                        values='count',
                        names='credential_type',
                        title="Credential Exposure Risk",
                        color_discrete_map={
                            'password': '#ff0000',
                            'email': '#ff8000',
                            'personal_info': '#ffff00',
                            'contact_details': '#00ff00'
                        }
                    )
                    st.plotly_chart(fig_cred, use_container_width=True)
                else:
                    # Show session-based credential data instead of "No data available"
                    session_credential_exposure = get_session_credential_exposure_risk(leaks)
                    if session_credential_exposure:
                        df_cred = pd.DataFrame(session_credential_exposure)
                        fig_cred = px.pie(
                            df_cred,
                            values='count',
                            names='credential_type',
                            title="Credential Exposure Risk (Session)",
                            color_discrete_map={
                                'password': '#ff0000',
                                'email': '#ff8000',
                                'personal_info': '#ffff00',
                                'contact_details': '#00ff00'
                            }
                        )
                        st.plotly_chart(fig_cred, use_container_width=True)
                    else:
                        st.info("No credential exposure risk data available for this session")
        
        # User Role Distribution
        st.markdown("### User Role Analysis")
        st.markdown("<br>", unsafe_allow_html=True)
        role_data = get_user_role_distribution(leaks)
        if role_data:
            df_role = pd.DataFrame(role_data)
            fig_role = px.pie(
                df_role,
                values='count',
                names='role',
                title="Leaks by User Role"
            )
            st.plotly_chart(fig_role, use_container_width=True)
        
        # Recent Leaks Table (Session-based)
        st.markdown("---")
        st.header("Recent Security Incidents")
        st.caption("⚠️ Shows incidents from current session only")
        st.markdown("<br>", unsafe_allow_html=True)
        
        if not leaks:
            st.success("No security incidents detected")
        else:
            # Convert to DataFrame for better display
            df_leaks = pd.DataFrame(leaks)
            
            # Add risk level color coding
            def color_risk_level(val):
                if val == 'critical':
                    return 'background-color: #ff0000; color: white'
                elif val == 'high':
                    return 'background-color: #ff8000; color: white'
                elif val == 'medium':
                    return 'background-color: #ffff00; color: black'
                elif val == 'low':
                    return 'background-color: #00ff00; color: black'
                return ''
            
            # Display recent leaks with styling
            if not df_leaks.empty:
                # Select important columns (use available columns)
                available_cols = ['created_at', 'user_role', 'category', 'risk_level', 'risk_score', 'summary']
                display_cols = [col for col in available_cols if col in df_leaks.columns]
                
                if display_cols:
                    df_display = df_leaks[display_cols].copy()
                    
                    # Format datetime if available
                    if 'created_at' in df_display.columns:
                        df_display['created_at'] = pd.to_datetime(df_display['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                    
                    # Apply styling if risk_level column exists
                    if 'risk_level' in df_display.columns:
                        styled_df = df_display.style.map(
                            color_risk_level, 
                            subset=['risk_level']
                        )
                        st.dataframe(styled_df, use_container_width=True)
                    else:
                        st.dataframe(df_display, use_container_width=True)
                else:
                    st.dataframe(df_leaks, use_container_width=True)
        
        # Add button to update security scan results
        st.markdown("---")
        if st.button("Update Security Scan Results"):
            # Calculate new security scan data based on current session
            new_scan_data = calculate_security_scan_data(leaks, session_dashboard_data)
            new_scan_data["hr_user"] = auth.get("name")
            new_scan_data["session_id"] = st.session_state.session_id
            
            # Save to database
            try:
                save_r = requests.post(f"{API_URL}/security-scan-results", json=new_scan_data, timeout=20)
                if save_r.status_code == 200:
                    st.success("Security scan results updated successfully!")
                    st.rerun()
                else:
                    st.error(f"Failed to update security scan results: {save_r.status_code}")
            except Exception as e:
                st.error(f"Failed to update security scan results: {e}")
        
        # Security Scan History Section
        st.markdown("---")
        st.header("Security Scan History")
        st.markdown("<br>", unsafe_allow_html=True)
        
        try:
            # Get security scan history
            history_r = requests.get(f"{API_URL}/security-scan-history", params={"limit": 5}, timeout=20)
            if history_r.status_code == 200:
                scan_history = history_r.json()
                
                if scan_history:
                    # Create a DataFrame for better display
                    history_data = []
                    for scan in scan_history:
                        history_data.append({
                            "Scan Date": scan.get("scan_date", ""),
                            "HR User": scan.get("hr_user", "Unknown"),
                            "Fake Names": scan.get("medical_records_count", 0),
                            "Jailbreak Attempts": scan.get("jailbreak_attempts_count", 0),
                            "PII/PHI Secrets": scan.get("pii_phi_secrets_count", 0),
                            "Risky Flows": scan.get("risky_flows_count", 0),
                            "Leaked Records": scan.get("leaked_records_count", 0),
                            "Resistance %": f"{scan.get('resistance_percentage', 100)}%"
                        })
                    
                    if history_data:
                        df_history = pd.DataFrame(history_data)
                        
                        # Format datetime if available
                        if "Scan Date" in df_history.columns:
                            df_history["Scan Date"] = pd.to_datetime(df_history["Scan Date"]).dt.strftime('%Y-%m-%d %H:%M')
                        
                        st.dataframe(df_history, use_container_width=True)
                        
                        # Show trend chart
                        if len(scan_history) > 1:
                            st.markdown("### Security Scan Trends")
                            trend_data = []
                            for scan in reversed(scan_history):  # Reverse to show chronological order
                                trend_data.append({
                                    "Date": scan.get("scan_date", ""),
                                    "Leaked Records": scan.get("leaked_records_count", 0),
                                    "Resistance %": scan.get("resistance_percentage", 100)
                                })
                            
                            if trend_data:
                                df_trend = pd.DataFrame(trend_data)
                                df_trend["Date"] = pd.to_datetime(df_trend["Date"]).dt.strftime('%Y-%m-%d')
                                
                                # Create trend chart
                                fig_trend = px.line(
                                    df_trend,
                                    x="Date",
                                    y=["Leaked Records", "Resistance %"],
                                    title="Security Scan Trends Over Time",
                                    markers=True
                                )
                                st.plotly_chart(fig_trend, use_container_width=True)
                else:
                    st.info("No security scan history available")
            else:
                st.warning("Could not load security scan history")
        except Exception as e:
            st.error(f"Failed to load security scan history: {e}")
        
    except Exception as e:
        st.error(f"Failed to load dashboard data: {e}")
    


def analyze_text_with_presidio(text):
    """Analyze text using Presidio for PII detection"""
    try:
        r = requests.post(
            f"{API_URL}/analyze-text",
            json={"text": text},
            timeout=10
        )
        if r.status_code == 200:
            return r.json()
        else:
            return {"entities": []}
    except Exception:
        return {"entities": []}

def calculate_dashboard_metrics(leaks):
    """Calculate dashboard metrics from actual leak data using Presidio analysis"""
    if not leaks:
        return {
            "fake_entities": {"fake_names": 0, "medical_records": 0, "api_keys": 0},
            "jailbreak_prompts": 0,
            "ai_behavior": {"pii_phi_secrets": 0, "external_calls": 0, "risky_flows": 0},
            "results": {"resistance_percentage": 100, "leaked_records": 0},
            "connections": {"third_party": 0, "high_risk": 0}
        }
    
    # Dynamic PII detection using Presidio
    pii_phi_secrets = 0
    fake_names = 0
    medical_records = 0
    api_keys = 0
    
    for leak in leaks:
        question = leak.get("question", "")
        answer = leak.get("answer_preview", "")
        
        # Analyze question and answer with Presidio
        question_analysis = analyze_text_with_presidio(question)
        answer_analysis = analyze_text_with_presidio(answer)
        
        # Count PII entities found
        if question_analysis.get("entities") or answer_analysis.get("entities"):
            pii_phi_secrets += 1
        
        # Check for fake name attempts based on leak type from backend
        if leak.get("leak_type") == "sensitive_data":
            # This could be either fake names or medical records, check the question content
            question_lower = leak.get("question", "").lower()
            if "salary" in question_lower or "pay" in question_lower or "compensation" in question_lower:
                fake_names += 1
            elif "medical" in question_lower or "health" in question_lower:
                medical_records += 1
            else:
                # Default to fake names for sensitive data
                fake_names += 1
        
        # Check for medical-related entities using Presidio
        medical_entities = ["MEDICAL_LICENSE", "UK_NHS", "MEDICAL_RECORD"]
        if any(entity in str(question_analysis.get("entities", [])) for entity in medical_entities):
            medical_records += 1
        
        # Check for API/credential related content using Presidio
        credential_entities = ["CRYPTO", "API_KEY", "CREDIT_CARD", "IBAN_CODE"]
        if any(entity in str(question_analysis.get("entities", [])) for entity in credential_entities):
            api_keys += 1
        

    
    # Count jailbreak attempts (dynamic detection)
    jailbreak_patterns = [
        'ignore', 'bypass', 'admin', 'system', 'override', 'hack', 'exploit',
        'break', 'crack', 'unauthorized', 'privilege', 'escalation', 'root'
    ]
    jailbreak_attempts = sum(1 for leak in leaks if any(pattern in (leak.get("question", "") or "").lower() 
                                                      for pattern in jailbreak_patterns))
    
    # Count risky flows (based on total leaks and risk scores)
    risky_flows = len(leaks)  # Each leak represents a risky flow
    
    # Calculate risk levels
    high_risk_leaks = sum(1 for leak in leaks if leak.get("risk_score", 0) >= 60)
    
    # Calculate resistance percentage (simplified)
    total_attempts = len(leaks) + 10  # Add baseline
    resisted_attempts = total_attempts - len(leaks)
    resistance_percentage = min(100, max(0, int((resisted_attempts / total_attempts) * 100)))
    
    return {
        "fake_entities": {
            "fake_names": fake_names,
            "medical_records": medical_records,
            "api_keys": api_keys
        },
        "jailbreak_prompts": jailbreak_attempts,
        "ai_behavior": {
            "pii_phi_secrets": pii_phi_secrets,
            "external_calls": 0,  # Placeholder
            "risky_flows": risky_flows
        },
        "results": {
            "resistance_percentage": resistance_percentage,
            "leaked_records": len(leaks)
        },
        "connections": {
            "third_party": 0,  # Placeholder
            "high_risk": high_risk_leaks
        }
    }


def calculate_security_scan_data(leaks, dashboard_data):
    """Calculate security scan data for persistent storage"""
    # Get current security scan results to add to existing counts
    try:
        current_scan_r = requests.get(f"{API_URL}/security-scan-results", timeout=20)
        if current_scan_r.status_code == 200:
            current_scan = current_scan_r.json()
            # Add new session data to existing persistent data
            fake_names_count = current_scan.get("fake_names_count", 0) + dashboard_data.get("fake_entities", {}).get("fake_names", 0)
            medical_records_count = current_scan.get("medical_records_count", 0) + dashboard_data.get("fake_entities", {}).get("medical_records", 0)
            api_keys_count = current_scan.get("api_keys_count", 0) + dashboard_data.get("fake_entities", {}).get("api_keys", 0)
            jailbreak_attempts_count = current_scan.get("jailbreak_attempts_count", 0) + dashboard_data.get("jailbreak_prompts", 0)
            pii_phi_secrets_count = current_scan.get("pii_phi_secrets_count", 0) + dashboard_data.get("ai_behavior", {}).get("pii_phi_secrets", 0)
            risky_flows_count = current_scan.get("risky_flows_count", 0) + dashboard_data.get("ai_behavior", {}).get("risky_flows", 0)
            external_calls_count = current_scan.get("external_calls_count", 0) + dashboard_data.get("ai_behavior", {}).get("external_calls", 0)
            leaked_records_count = current_scan.get("leaked_records_count", 0) + dashboard_data.get("results", {}).get("leaked_records", 0)
        else:
            # Use only current session data if no existing scan
            fake_names_count = dashboard_data.get("fake_entities", {}).get("fake_names", 0)
            medical_records_count = dashboard_data.get("fake_entities", {}).get("medical_records", 0)
            api_keys_count = dashboard_data.get("fake_entities", {}).get("api_keys", 0)
            jailbreak_attempts_count = dashboard_data.get("jailbreak_prompts", 0)
            pii_phi_secrets_count = dashboard_data.get("ai_behavior", {}).get("pii_phi_secrets", 0)
            risky_flows_count = dashboard_data.get("ai_behavior", {}).get("risky_flows", 0)
            external_calls_count = dashboard_data.get("ai_behavior", {}).get("external_calls", 0)
            leaked_records_count = dashboard_data.get("results", {}).get("leaked_records", 0)
    except Exception:
        # Fallback to current session data only
        fake_names_count = dashboard_data.get("fake_entities", {}).get("fake_names", 0)
        medical_records_count = dashboard_data.get("fake_entities", {}).get("medical_records", 0)
        api_keys_count = dashboard_data.get("fake_entities", {}).get("api_keys", 0)
        jailbreak_attempts_count = dashboard_data.get("jailbreak_prompts", 0)
        pii_phi_secrets_count = dashboard_data.get("ai_behavior", {}).get("pii_phi_secrets", 0)
        risky_flows_count = dashboard_data.get("ai_behavior", {}).get("risky_flows", 0)
        external_calls_count = dashboard_data.get("ai_behavior", {}).get("external_calls", 0)
        leaked_records_count = dashboard_data.get("results", {}).get("leaked_records", 0)
    
    # Calculate overall resistance percentage based on accumulated data
    total_attempts = leaked_records_count + 10  # Add baseline
    resisted_attempts = total_attempts - leaked_records_count
    resistance_percentage = min(100, max(0, int((resisted_attempts / total_attempts) * 100)))
    
    return {
        "fake_names_count": fake_names_count,
        "medical_records_count": medical_records_count,
        "api_keys_count": api_keys_count,
        "jailbreak_attempts_count": jailbreak_attempts_count,
        "pii_phi_secrets_count": pii_phi_secrets_count,
        "risky_flows_count": risky_flows_count,
        "external_calls_count": external_calls_count,
        "resistance_percentage": resistance_percentage,
        "leaked_records_count": leaked_records_count
    }


def generate_security_recommendations(leaks, dashboard_data):
    """Generate security recommendations based on leak data"""
    recommendations = []
    
    if not leaks:
        recommendations.append("No immediate action required - system is secure")
        return recommendations
    
    # Analyze patterns and generate recommendations
    high_risk_count = sum(1 for leak in leaks if leak.get("risk_score", 0) >= 60)
    
    if high_risk_count > 0:
        recommendations.append("Implement additional security monitoring for high-risk activities")
    
    # Check for compensation data leaks (dynamic detection)
    compensation_patterns = ['salary', 'pay', 'compensation', 'bonus', 'income', 'wage']
    compensation_leaks = sum(1 for leak in leaks if any(pattern in (leak.get("summary", "") or "").lower() 
                                                      for pattern in compensation_patterns))
    if compensation_leaks > 0:
        recommendations.append("Add guardrails for prompt injection to prevent compensation data access")
    
    # Check for bulk data requests (dynamic detection)
    bulk_patterns = ['all', 'everyone', 'list all', 'show all', 'get all', 'every employee', 'entire']
    bulk_requests = sum(1 for leak in leaks if any(pattern in (leak.get("question", "") or "").lower() 
                                                  for pattern in bulk_patterns))
    if bulk_requests > 0:
        recommendations.append("Implement rate limiting for bulk data requests")
    
    # General recommendations
    if len(leaks) > 5:
        recommendations.append("Review and update access control policies")
    
    if not recommendations:
        recommendations.append("Monitor system for additional security patterns")
    
    return recommendations


def get_data_exposure_risk(leaks):
    """Get data exposure risk distribution from leak data using Presidio analysis"""
    if not leaks:
        return []
    
    # Dynamic risk categorization based on Presidio entity types
    risk_categories = {}
    
    for leak in leaks:
        question = leak.get("question", "")
        answer = leak.get("answer_preview", "")
        
        # Analyze both question and answer with Presidio
        question_analysis = analyze_text_with_presidio(question)
        answer_analysis = analyze_text_with_presidio(answer)
        
        # Process entities from both analyses
        all_entities = []
        if question_analysis.get("entities"):
            all_entities.extend(question_analysis["entities"])
        if answer_analysis.get("entities"):
            all_entities.extend(answer_analysis["entities"])
        
        # Categorize entities dynamically
        for entity in all_entities:
            entity_type = entity.get("entity_type", "")
            
            # Dynamic categorization based on entity type
            if entity_type in ["PERSON", "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE", "NRP"]:
                category = "personal_info"
            elif entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER"]:
                category = "contact_details"
            elif entity_type in ["LOCATION", "ADDRESS"]:
                category = "address_info"
            elif entity_type in ["CREDIT_CARD", "IBAN_CODE", "US_BANK_NUMBER"]:
                category = "financial_data"
            elif entity_type in ["MEDICAL_LICENSE", "UK_NHS", "MEDICAL_RECORD"]:
                category = "medical_data"
            elif entity_type in ["IP_ADDRESS", "CRYPTO"]:
                category = "technical_data"
            elif entity_type in ["DATE_TIME"]:
                category = "temporal_data"
            else:
                category = "other_sensitive_data"
            
            risk_categories[category] = risk_categories.get(category, 0) + 1
    
    return [{"risk_type": category, "count": count} for category, count in risk_categories.items() if count > 0]


def get_credential_exposure_risk(leaks):
    """Get credential exposure risk distribution from leak data using Presidio analysis"""
    if not leaks:
        return []
    
    # Dynamic credential risk categorization based on Presidio entity types
    credential_categories = {}
    
    for leak in leaks:
        question = leak.get("question", "")
        answer = leak.get("answer_preview", "")
        
        # Analyze both question and answer with Presidio
        question_analysis = analyze_text_with_presidio(question)
        answer_analysis = analyze_text_with_presidio(answer)
        
        # Process entities from both analyses
        all_entities = []
        if question_analysis.get("entities"):
            all_entities.extend(question_analysis["entities"])
        if answer_analysis.get("entities"):
            all_entities.extend(answer_analysis["entities"])
        
        # Categorize entities dynamically for credential exposure
        for entity in all_entities:
            entity_type = entity.get("entity_type", "")
            
            # Dynamic categorization based on entity type
            if entity_type in ["EMAIL_ADDRESS"]:
                category = "email_credentials"
            elif entity_type in ["PHONE_NUMBER"]:
                category = "contact_credentials"
            elif entity_type in ["PERSON", "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE"]:
                category = "identity_credentials"
            elif entity_type in ["CREDIT_CARD", "IBAN_CODE", "US_BANK_NUMBER"]:
                category = "financial_credentials"
            elif entity_type in ["IP_ADDRESS", "CRYPTO"]:
                category = "technical_credentials"
            elif entity_type in ["LOCATION", "ADDRESS"]:
                category = "location_credentials"
            else:
                category = "other_credentials"
            
            credential_categories[category] = credential_categories.get(category, 0) + 1
    
    return [{"credential_type": category, "count": count} for category, count in credential_categories.items() if count > 0]


def get_session_data_exposure_risk(leaks):
    """Get session-based data exposure risk distribution from leak data"""
    if not leaks:
        return []
    
    # Session-based risk categorization based on leak types and questions
    risk_categories = {}
    
    for leak in leaks:
        question = leak.get("question", "").lower()
        leak_type = leak.get("leak_type", "")
        category = leak.get("category", "")
        
        # Categorize based on leak type and question content
        if leak_type == "fake_name_attempt" or "salary" in question or "pay" in question:
            risk_categories["compensation_data"] = risk_categories.get("compensation_data", 0) + 1
        elif leak_type == "sensitive_data" or "medical" in question or "health" in question:
            risk_categories["medical_data"] = risk_categories.get("medical_data", 0) + 1
        elif "email" in question or "phone" in question or "contact" in question:
            risk_categories["contact_details"] = risk_categories.get("contact_details", 0) + 1
        elif "address" in question or "location" in question:
            risk_categories["address_info"] = risk_categories.get("address_info", 0) + 1
        elif "api" in question or "key" in question or "credential" in question:
            risk_categories["technical_data"] = risk_categories.get("technical_data", 0) + 1
        elif "all" in question or "everyone" in question or "bulk" in question:
            risk_categories["bulk_data"] = risk_categories.get("bulk_data", 0) + 1
        else:
            risk_categories["general_sensitive"] = risk_categories.get("general_sensitive", 0) + 1
    
    return [{"risk_type": category, "count": count} for category, count in risk_categories.items() if count > 0]


def get_session_credential_exposure_risk(leaks):
    """Get session-based credential exposure risk distribution from leak data"""
    if not leaks:
        return []
    
    # Session-based credential risk categorization
    credential_categories = {}
    
    for leak in leaks:
        question = leak.get("question", "").lower()
        leak_type = leak.get("leak_type", "")
        risk_score = leak.get("risk_score", 0)
        
        # Categorize based on question content and risk score
        if "email" in question or leak_type == "contact_information":
            credential_categories["email_credentials"] = credential_categories.get("email_credentials", 0) + 1
        elif "phone" in question or "contact" in question:
            credential_categories["contact_credentials"] = credential_categories.get("contact_credentials", 0) + 1
        elif "salary" in question or "pay" in question or leak_type == "compensation_data":
            credential_categories["financial_credentials"] = credential_categories.get("financial_credentials", 0) + 1
        elif "address" in question or "location" in question:
            credential_categories["location_credentials"] = credential_categories.get("location_credentials", 0) + 1
        elif "api" in question or "key" in question or leak_type == "credentials":
            credential_categories["technical_credentials"] = credential_categories.get("technical_credentials", 0) + 1
        elif risk_score > 50:  # High risk leaks
            credential_categories["high_risk_credentials"] = credential_categories.get("high_risk_credentials", 0) + 1
        else:
            credential_categories["general_credentials"] = credential_categories.get("general_credentials", 0) + 1
    
    return [{"credential_type": category, "count": count} for category, count in credential_categories.items() if count > 0]


def get_risk_level_distribution(leaks):
    """Get risk level distribution from leak data"""
    if not leaks:
        return []
    
    risk_counts = {}
    for leak in leaks:
        level = leak.get("risk_level", "low")
        risk_counts[level] = risk_counts.get(level, 0) + 1
    
    return [{"level": level, "count": count} for level, count in risk_counts.items()]


def get_category_distribution(leaks):
    """Get category distribution from leak data"""
    if not leaks:
        return []
    
    category_counts = {}
    for leak in leaks:
        category = leak.get("category", "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
    
    return [{"category": category, "count": count} for category, count in category_counts.items()]


def get_user_role_distribution(leaks):
    """Get user role distribution from leak data"""
    if not leaks:
        return []
    
    role_counts = {}
    for leak in leaks:
        role = leak.get("user_role", "unknown")
        role_counts[role] = role_counts.get(role, 0) + 1
    
    return [{"role": role, "count": count} for role, count in role_counts.items()]



if "messages" not in st.session_state:
    st.session_state.messages = []


if not auth["logged_in"]:
    tabs = st.tabs(["Login", "Register"])
    with tabs[0]:
        show_login()
    with tabs[1]:
        show_register()
else:
    show_chat_sidebar()

    if st.session_state.view == "leaks" and auth.get("role") == "HR":
        show_leaks_view()
    elif st.session_state.view == "history":
        st.title("Chat History")
        st.caption("Last 30 chats stored per role. Delete any item to free a slot.")
        role = auth.get("role") or "Visitor"
        
        # Search bar and CSV download section
        st.markdown("### Search & Export")
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            search_query = st.text_input("Search by keywords, names, or messages", key="chat_search", placeholder="Enter search terms...")
        
        with col2:
            if st.button("Search", key="search_button"):
                st.session_state.search_clicked = True
        
        with col3:
            if st.button("Download CSV", key="download_csv_button"):
                st.session_state.download_clicked = True
        
        # Handle search
        if st.session_state.get("search_clicked", False):
            st.session_state.search_clicked = False
            try:
                search_data = {
                    "role": role,
                    "search_query": search_query if search_query else None
                }
                r = requests.post(f"{API_URL}/chat-history/search", json=search_data, timeout=15)
                if r.status_code != 200:
                    st.error("Failed to search chat history")
                    items = []
                else:
                    items = r.json() or []
                    if not items:
                        st.info("No chat history found for your search criteria")
                    else:
                        st.markdown(f"**Found {len(items)} chat(s)**")
            except Exception as e:
                st.error(f"Failed to search history: {e}")
                items = []
        else:
            # Load regular chat history
            try:
                r = requests.get(f"{API_URL}/chat-history", params={"role": role}, timeout=15)
                if r.status_code != 200:
                    st.error("Failed to load chat history")
                    items = []
                else:
                    items = r.json() or []
            except Exception as e:
                st.error(f"Failed to load history: {e}")
                items = []
        
        # Handle CSV download
        if st.session_state.get("download_clicked", False):
            st.session_state.download_clicked = False
            try:
                export_data = {
                    "role": role,
                    "search_query": search_query if search_query else None
                }
                export_r = requests.post(f"{API_URL}/chat-history/export-csv", json=export_data, timeout=30)
                if export_r.status_code == 200:
                    filename = f"chat_history_{role}_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    st.download_button(
                        label="Click to download CSV",
                        data=export_r.content,
                        file_name=filename,
                        mime="text/csv"
                    )
                    st.success("CSV file ready for download!")
                else:
                    st.error(f"Failed to export CSV: {export_r.status_code}")
            except Exception as e:
                st.error(f"Failed to export CSV: {e}")
        
        # Display chat history
        if not items:
            if not st.session_state.get("search_clicked", False):
                st.info("No chat history yet for your role")
        else:
            for item in items:
                created = item.get("created_at", "")
                msg = item.get("message", "")
                resp = item.get("response", "")
                sensitivity = (item.get("sensitivity") or "OK").upper()
                # Boxed layout using expander (always expanded) for visual separation
                label_date = pd.to_datetime(created).strftime('%Y-%m-%d %H:%M') if created else ''
                with st.expander(f"Date: {label_date}", expanded=True):
                    cols = st.columns([6, 1, 1])
                    with cols[0]:
                        st.markdown("**You:** " + (msg or ""))
                        st.markdown("**Bot:** " + (resp or ""))
                    with cols[1]:
                        if sensitivity == "SENSITIVE":
                            st.markdown("<div style='display:inline-block;padding:2px 8px;border:1px solid #ff4d4f;border-radius:6px;background:#fff5f5;color:#a8071a;font-size:12px;'>Sensitive</div>", unsafe_allow_html=True)
                        else:
                            st.markdown("<div style='display:inline-block;padding:2px 8px;border:1px solid #1677ff;border-radius:6px;background:#f0f7ff;color:#0958d9;font-size:12px;'>Non Sensitive</div>", unsafe_allow_html=True)
                    with cols[2]:
                        if st.button("🗑️", key=f"del_{item.get('id')}"):
                            try:
                                dr = requests.delete(f"{API_URL}/chat-history/{item.get('id')}", timeout=10)
                                if dr.status_code == 200:
                                    st.success("Deleted")
                                    st.rerun()
                                else:
                                    st.error("Delete failed")
                            except Exception as e:
                                st.error(f"Delete failed: {e}")
        
    else:
        show_chat_header()

        for msg in st.session_state.messages:
            with st.chat_message("user" if msg["sender"] == "user" else "assistant"):
                st.markdown(msg["text"])

        blocked_remote, _ = get_block_status()
        if not blocked_remote and st.session_state.locally_blocked:
            st.session_state.locally_blocked = False
        blocked = blocked_remote or st.session_state.locally_blocked

        if blocked:
            st.info("You are temporarily blocked")
            time.sleep(1)
            st.rerun()
        else:
            prompt = st.chat_input("Ask about the organization...")
            if prompt:
                st.session_state.messages.append({"sender": "user", "text": prompt})
                with st.chat_message("assistant"):
                    with st.spinner("Thinking..."):
                        try:
                            r = requests.post(
                                f"{API_URL}/chat",
                                json={"message": prompt, "role": auth.get("role"), "name": auth.get("name"), "session_id": st.session_state.session_id},
                                timeout=30,
                            )
                            if r.status_code == 200:
                                try:
                                    reply = r.json().get("reply", "")
                                except Exception:
                                    reply = r.text or ""
                            else:
                                try:
                                    err = r.json().get("detail", r.text)
                                except Exception:
                                    err = r.text
                                reply = f"Error: {r.status_code} {err}"
                        except Exception as e:
                            reply = f"Failed to reach API: {e}"
                        st.markdown(reply)
                        st.session_state.messages.append({"sender": "assistant", "text": reply})
                        if reply.strip() == "You are temporarily blocked":
                            st.session_state.locally_blocked = True
                            st.rerun()


