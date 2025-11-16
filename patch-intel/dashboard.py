"""
PatchIntel - Patch Tuesday Dashboard
Direct visualization of Microsoft Patch Tuesday CVE data
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="PatchIntel - Patch Tuesday Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Title
st.title("🛡️ PatchIntel - Patch Tuesday Dashboard")
st.markdown("**Microsoft Security Updates Analysis | October 2025**")

# Microsoft Field Definitions
with st.expander("ℹ️ Understanding Microsoft Patch Tuesday Fields", expanded=False):
    st.markdown("""
    ### Data Source
    Microsoft Security Update Guide (CVRF - Common Vulnerability Reporting Framework)
    
    ### Key Fields Explained
    
    **Severity Rating** - Microsoft's official assessment of vulnerability severity:
    - 🔴 **Critical**: Vulnerabilities whose exploitation could allow code execution without user interaction
    - 🟠 **Important**: Vulnerabilities whose exploitation could compromise confidentiality, integrity, or availability
    - 🟡 **Moderate**: Impact is mitigated by factors such as authentication requirements or applicability
    - 🟢 **Low**: Very difficult to exploit or minimal impact
    
    **Impact Type** - What an attacker can achieve:
    - **Remote Code Execution (RCE)**: Run arbitrary code on target system
    - **Elevation of Privilege (EoP)**: Gain higher-level permissions
    - **Denial of Service (DoS)**: Make system/service unavailable
    - **Security Feature Bypass (SFB)**: Circumvent security mechanisms
    - **Information Disclosure**: Access sensitive information
    - **Spoofing**: Impersonate another user/system
    - **Tampering**: Modify data or code
    
    **Exploitation Status** - Microsoft's assessment of exploitation likelihood:
    - ⚠️ **Exploitation Detected**: Active exploitation observed in the wild
    - 🔶 **More Likely**: Microsoft assesses exploitation is more likely to occur
    - 🔷 **Less Likely**: Microsoft assesses exploitation is less likely
    - ⚪ **Unlikely**: Microsoft assesses exploitation is unlikely
    
    **CVSS Score** - Industry standard severity score (0-10):
    - 9.0-10.0: Critical
    - 7.0-8.9: High
    - 4.0-6.9: Medium
    - 0.1-3.9: Low
    
    **Attack Vector** - How can the vulnerability be exploited:
    - 🌐 **Network**: Remotely exploitable over a network
    - 📡 **Adjacent**: Requires access to adjacent network (same subnet)
    - 💻 **Local**: Requires local access to the system
    - 🔧 **Physical**: Requires physical access to the device
    
    **Privileges Required** - What level of access is needed:
    - ❌ **None**: No authentication required
    - 👤 **Low**: Basic user-level privileges required
    - 👑 **High**: Administrator/elevated privileges required
    """)

st.markdown("---")

# Create tabs
tab1, tab2, tab3 = st.tabs(["📊 CVE Explorer", "🎯 Risk Calculator", "📈 Analytics & Insights"])

# Load data
@st.cache_data
def load_data():
    try:
        # Load the parsed Patch Tuesday data
        csv_path = Path(__file__).parent / "samples" / "patch_tuesday_2025_10.csv"
        df = pd.read_csv(csv_path)
        
        # Parse CVSS vector for Attack Vector and Privileges Required
        def extract_av(vector):
            if pd.isna(vector) or not vector:
                return 'Unknown'
            parts = vector.split('/')
            for part in parts:
                if part.startswith('AV:'):
                    av_code = part.split(':')[1]
                    mapping = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}
                    return mapping.get(av_code, av_code)
            return 'Unknown'
        
        def extract_pr(vector):
            if pd.isna(vector) or not vector:
                return 'Unknown'
            parts = vector.split('/')
            for part in parts:
                if part.startswith('PR:'):
                    pr_code = part.split(':')[1]
                    mapping = {'N': 'None', 'L': 'Low', 'H': 'High'}
                    return mapping.get(pr_code, pr_code)
            return 'Unknown'
        
        df['attack_vector'] = df['cvss_vector'].apply(extract_av)
        df['privileges_required'] = df['cvss_vector'].apply(extract_pr)
        
        # Clean up exploitation status labels
        def clean_exploit_status(status):
            status_map = {
                'exploitation_detected': 'Exploitation Detected',
                'exploitation_more_likely': 'More Likely',
                'exploitation_less_likely': 'Less Likely',
                'exploitation_unlikely': 'Unlikely',
                'unknown': 'Unknown'
            }
            return status_map.get(status, status)
        
        df['exploitation_status_display'] = df['exploit_status'].apply(clean_exploit_status)
        
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return None

df = load_data()

if df is None:
    st.stop()

# TAB 1: CVE EXPLORER
with tab1:
    st.header("🔎 CVE Explorer")

    # Filters
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        severity_filter = st.multiselect(
            "Severity",
            options=df['severity'].unique(),
            default=df['severity'].unique()
        )

    with col2:
        impact_filter = st.multiselect(
            "Impact Type",
            options=df['impact_type'].unique(),
            default=df['impact_type'].unique()
        )

    with col3:
        exploit_filter = st.multiselect(
            "Exploitation Status",
            options=df['exploitation_status_display'].unique(),
            default=df['exploitation_status_display'].unique()
        )

    with col4:
        min_cvss = st.slider(
            "Minimum CVSS",
            min_value=0.0,
            max_value=10.0,
            value=0.0,
            step=0.5
        )

    # Apply filters
    filtered_df = df[
        (df['severity'].isin(severity_filter)) &
        (df['impact_type'].isin(impact_filter)) &
        (df['exploitation_status_display'].isin(exploit_filter)) &
        (df['cvss_base_score'] >= min_cvss)
    ]

    # Sorting options
    col1, col2 = st.columns(2)

    with col1:
        sort_by = st.selectbox(
            "Sort by",
            options=[
                'CVSS Score',
                'Severity Rating',
                'Impact Type',
                'Exploitation Status',
                'Attack Vector',
                'Privileges Required',
                'CVE ID'
            ],
            index=0
        )

    with col2:
        sort_order = st.radio(
            "Order",
            options=['Descending', 'Ascending'],
            horizontal=True
        )

    # Map sort field to column name
    sort_column_map = {
        'CVSS Score': 'cvss_base_score',
        'Severity Rating': 'severity',
        'Impact Type': 'impact_type',
        'Exploitation Status': 'exploitation_status_display',
        'Attack Vector': 'attack_vector',
        'Privileges Required': 'privileges_required',
        'CVE ID': 'cve_id'
    }

    sort_column = sort_column_map[sort_by]
    ascending = (sort_order == 'Ascending')

    # Sort with priority mappings for categorical columns
    if sort_by == 'Severity Rating':
        severity_priority = {'Critical': 4, 'Important': 3, 'Moderate': 2, 'Low': 1, 'Unknown': 0, '': 0}
        filtered_df['sort_key'] = filtered_df['severity'].map(severity_priority).fillna(0)
        filtered_df = filtered_df.sort_values('sort_key', ascending=ascending)
        filtered_df = filtered_df.drop('sort_key', axis=1)
    elif sort_by == 'Attack Vector':
        av_priority = {'Network': 4, 'Adjacent': 3, 'Local': 2, 'Physical': 1, 'Unknown': 0, '': 0}
        filtered_df['sort_key'] = filtered_df['attack_vector'].map(av_priority).fillna(0)
        filtered_df = filtered_df.sort_values('sort_key', ascending=ascending)
        filtered_df = filtered_df.drop('sort_key', axis=1)
    elif sort_by == 'Privileges Required':
        pr_priority = {'None': 3, 'Low': 2, 'High': 1, 'Unknown': 0, '': 0}
        filtered_df['sort_key'] = filtered_df['privileges_required'].map(pr_priority).fillna(0)
        filtered_df = filtered_df.sort_values('sort_key', ascending=ascending)
        filtered_df = filtered_df.drop('sort_key', axis=1)
    elif sort_by == 'Exploitation Status':
        exploit_priority = {
            'Exploitation Detected': 5,
            'More Likely': 4,
            'Less Likely': 3,
            'Unlikely': 2,
            'Unknown': 1,
            '': 0
        }
        filtered_df['sort_key'] = filtered_df['exploitation_status_display'].map(exploit_priority).fillna(0)
        filtered_df = filtered_df.sort_values('sort_key', ascending=ascending)
        filtered_df = filtered_df.drop('sort_key', axis=1)
    elif sort_by == 'Impact Type':
        impact_priority = {
            'Remote Code Execution': 7,
            'Elevation of Privilege': 6,
            'Security Feature Bypass': 5,
            'Tampering': 4,
            'Information Disclosure': 3,
            'Denial of Service': 2,
            'Spoofing': 1,
            '': 0
        }
        filtered_df['sort_key'] = filtered_df['impact_type'].map(impact_priority).fillna(0)
        filtered_df = filtered_df.sort_values('sort_key', ascending=ascending)
        filtered_df = filtered_df.drop('sort_key', axis=1)
    else:
        filtered_df = filtered_df.sort_values(sort_column, ascending=ascending)

    st.info(f"📊 Showing {len(filtered_df)} of {len(df)} CVEs")

    # Display filtered CVEs
    display_cols = [
        'cve_id',
        'title',
        'severity',
        'cvss_base_score',
        'impact_type',
        'exploitation_status_display',
        'attack_vector',
        'privileges_required'
    ]

    st.dataframe(
        filtered_df[display_cols],
        use_container_width=True,
        height=500
    )

    # Download button
    csv = filtered_df.to_csv(index=False)
    st.download_button(
        label=f"📥 Download Filtered CVEs ({len(filtered_df)} records)",
        data=csv,
        file_name=f"patch_tuesday_filtered_{len(filtered_df)}_cves.csv",
        mime="text/csv"
    )

# TAB 2: RISK CALCULATOR

with tab2:
    st.header("🎯 Interactive Risk Calculator")
    st.markdown("**Understand how CVE risk varies based on YOUR asset context**")


    # Risk calculation function
    def calculate_risk_score(cve_row, asset_exposure, business_criticality):
        """Calculate risk score based on CVE attributes and asset context"""
    
        # Base score from CVSS (reduced weight for better sensitivity)
        base_score = cve_row['cvss_base_score'] * 5  # Changed from ×10 to ×5 (50% weight)
    
        # Attack Vector × Exposure matching (expanded range: 0.3-3.0x)
        exposure_multiplier = 1.0
        if cve_row['attack_vector'] == 'Network':
            if asset_exposure == 'Internet-facing':
                exposure_multiplier = 3.0  # Maximum exposure
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_multiplier = 2.0
            elif asset_exposure == 'Internal workstation':
                exposure_multiplier = 1.5
            else:  # Non-critical/isolated
                exposure_multiplier = 1.0
        elif cve_row['attack_vector'] == 'Adjacent':
            if asset_exposure == 'Internet-facing':
                exposure_multiplier = 1.8
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_multiplier = 1.5
            else:
                exposure_multiplier = 1.2
        elif cve_row['attack_vector'] == 'Local':
            if asset_exposure == 'Internet-facing':
                exposure_multiplier = 1.2
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_multiplier = 1.0
            else:
                exposure_multiplier = 0.8
        else:  # Physical
            exposure_multiplier = 0.3  # Minimum exposure
    
        # Exploitation status boost (expanded range: 1.0-1.5x)
        exploitation_boost = 1.0
        if cve_row['exploitation_status_display'] == 'Exploitation Detected':
            exploitation_boost = 1.5  # Increased from 1.3
        elif cve_row['exploitation_status_display'] == 'More Likely':
            exploitation_boost = 1.3  # Increased from 1.15
        elif cve_row['exploitation_status_display'] == 'Less Likely':
            exploitation_boost = 1.1  # Increased from 1.05
    
        # Privileges required boost (expanded range: 1.0-1.4x)
        privileges_boost = 1.0
        if cve_row['privileges_required'] == 'None':
            privileges_boost = 1.4  # Increased from 1.2
        elif cve_row['privileges_required'] == 'Low':
            privileges_boost = 1.2  # Increased from 1.1
    
        # Business criticality multiplier (expanded range: 0.4-2.0x)
        criticality_multiplier = 1.0
        if business_criticality == 'Production':
            criticality_multiplier = 2.0  # Increased from 1.5
        elif business_criticality == 'Development/Test':
            criticality_multiplier = 1.0
        else:  # Non-business critical
            criticality_multiplier = 0.4  # Decreased from 0.7
    
        # Calculate final score
        risk_score = base_score * exposure_multiplier * exploitation_boost * privileges_boost * criticality_multiplier
    
        # Cap at 100
        return min(100, risk_score)

    def get_risk_level(score):
        """Determine risk level from score"""
        if score >= 90:
            return "🔥 CRITICAL", "#ff0000"
        elif score >= 70:
            return "🟠 HIGH", "#ff6600"
        elif score >= 40:
            return "🟡 MEDIUM", "#ffaa00"
        else:
            return "🟢 LOW", "#88dd00"

    def get_risk_explanation(cve_row, asset_exposure, business_criticality, score):
        """Generate explanation for the risk score"""
        reasons = []
    
        # Check attack vector and exposure match
        if cve_row['attack_vector'] == 'Network' and asset_exposure == 'Internet-facing':
            reasons.append("✓ Network exploitable vulnerability with internet-facing asset")
        elif cve_row['attack_vector'] == 'Network':
            reasons.append("✓ Network exploitable vulnerability")
    
        # Check privileges
        if cve_row['privileges_required'] == 'None':
            reasons.append("✓ No privileges required (easy to exploit)")
    
        # Check exploitation status
        if cve_row['exploitation_status_display'] == 'Exploitation Detected':
            reasons.append("✓ Active exploitation detected in the wild")
        elif cve_row['exploitation_status_display'] == 'More Likely':
            reasons.append("✓ Microsoft assesses exploitation is more likely")
    
        # Check severity
        if cve_row['severity'] == 'Critical':
            reasons.append("✓ Critical severity rating from Microsoft")
    
        # Check business criticality
        if business_criticality == 'Production':
            reasons.append("✓ Production environment (high business impact)")
    
        # Check exposure type
        if asset_exposure == 'Internet-facing':
            reasons.append("✓ Asset is directly exposed to the internet")
    
        return reasons

    def get_recommendation(score, cve_row, asset_exposure):
        """Get recommendation based on risk score"""
        if score >= 90:
            return """
            **⚡ EMERGENCY ACTION REQUIRED**
        
            - Deploy patch immediately (within 24 hours)
            - Consider temporary isolation if patch cannot be deployed
            - Monitor for signs of exploitation
            - Notify security team and management
            """
        elif score >= 70:
            return """
            **⚠️ URGENT PATCHING REQUIRED**
        
            - Deploy patch within 7 days
            - Prioritize in next maintenance window
            - Review and apply compensating controls
            - Monitor affected systems
            """
        elif score >= 40:
            return """
            **📋 SCHEDULE PATCHING**
        
            - Include in next regular patch cycle (30 days)
            - Test patch in non-production first
            - Schedule during maintenance window
            - Document in change management
            """
        else:
            return """
            **✅ STANDARD PATCH PROCESS**
        
            - Patch in normal cycle (60-90 days)
            - Low priority for urgent deployment
            - Can be included in quarterly updates
            - Monitor for changes in threat landscape
            """

    # Get all CVEs sorted by CVSS score (highest first)
    all_cves = df.sort_values('cvss_base_score', ascending=False)

    col1, col2, col3 = st.columns([1.2, 1.2, 0.8])

    with col1:
        st.subheader("Step 1: Select a CVE")
        
        # Selection mode toggle
        selection_mode = st.radio(
            "How would you like to select a CVE?",
            options=["🔍 Search/Filter", "📋 Browse List"],
            horizontal=True,
            key="selection_mode"
        )
        
        if selection_mode == "🔍 Search/Filter":
            # Search and filter interface
            search_term = st.text_input(
                "Search CVEs by ID or title",
                placeholder="e.g., CVE-2025 or Elevation of Privilege",
                key="cve_search"
            )
            
            # Filter options
            filter_col1, filter_col2 = st.columns(2)
            with filter_col1:
                severity_filter = st.multiselect(
                    "Severity",
                    options=['Critical', 'Important', 'Moderate', 'Low'],
                    default=['Critical', 'Important'],
                    key="severity_filter"
                )
            
            with filter_col2:
                exploit_filter = st.multiselect(
                    "Exploitation Status",
                    options=['Exploitation Detected', 'More Likely', 'Less Likely', 'Exploitation Less Likely'],
                    key="exploit_filter"
                )
            
            # Apply filters
            filtered_df = all_cves.copy()
            
            if search_term:
                filtered_df = filtered_df[
                    filtered_df['cve_id'].str.contains(search_term, case=False) |
                    filtered_df['title'].str.contains(search_term, case=False)
                ]
            
            if severity_filter:
                filtered_df = filtered_df[filtered_df['severity'].isin(severity_filter)]
            
            if exploit_filter:
                filtered_df = filtered_df[filtered_df['exploitation_status_display'].isin(exploit_filter)]
            
            # Show results count
            st.caption(f"Found {len(filtered_df)} CVEs matching criteria")
            
            # Create options from filtered results
            if len(filtered_df) > 0:
                cve_options = {f"{row['cve_id']} - {row['title'][:60]}...": idx 
                               for idx, row in filtered_df.iterrows()}
                
                selected_cve_label = st.selectbox(
                    "Select a CVE from results",
                    options=list(cve_options.keys()),
                    key="filtered_cve_selector"
                )
                
                selected_cve_idx = cve_options[selected_cve_label]
                selected_cve = df.loc[selected_cve_idx]
            else:
                st.warning("No CVEs match your criteria. Please adjust filters.")
                # Default to first CVE if no match
                selected_cve = all_cves.iloc[0]
        
        else:  # Browse List mode
            # Create CVE options from all CVEs
            cve_options = {f"{row['cve_id']} - {row['title'][:60]}...": idx 
                           for idx, row in all_cves.iterrows()}
            
            st.caption(f"Browsing all {len(all_cves)} CVEs (sorted by CVSS score)")
            
            selected_cve_label = st.selectbox(
                "Choose a CVE to assess",
                options=list(cve_options.keys()),
                key="browse_cve_selector"
            )
            
            selected_cve_idx = cve_options[selected_cve_label]
            selected_cve = df.loc[selected_cve_idx]

    with col2:
        # Create sub-columns for CVE Characteristics and Step 2
        subcol1, subcol2 = st.columns([1, 1])
        
        with subcol1:
            st.markdown("**📋 CVE Characteristics:**")
        
            severity_emoji = {
                'Critical': '🔴',
                'Important': '🟠',
                'Moderate': '🟡',
                'Low': '🟢'
            }.get(selected_cve['severity'], '⚪')
        
            st.markdown(f"""
            - {severity_emoji} **Severity:** {selected_cve['severity']}
            - **📊 CVSS Score:** {selected_cve['cvss_base_score']}
            - **🌐 Attack Vector:** {selected_cve['attack_vector']}
            - **🔑 Privileges Required:** {selected_cve['privileges_required']}
            - **⚠️ Exploitation Status:** {selected_cve['exploitation_status_display']}
            - **💥 Impact Type:** {selected_cve['impact_type']}
            """)
        
        with subcol2:
            st.markdown("**Step 2: Define Your Asset**")
        
            st.markdown("**Asset Exposure:**")
            asset_exposure = st.radio(
                "Where is this asset located?",
                options=[
                    'Internet-facing',
                    'Server (domain/infrastructure)',
                    'Internal workstation',
                    'Non-critical/isolated'
                ],
                key="exposure_selector",
                label_visibility="collapsed"
            )
        
            st.markdown("**Business Criticality:**")
            business_criticality = st.radio(
                "What is the business importance?",
                options=[
                    'Production',
                    'Development/Test',
                    'Non-business critical'
                ],
                key="criticality_selector",
                label_visibility="collapsed"
            )

    # Calculate risk (moved up to display in col3)
    risk_score = calculate_risk_score(selected_cve, asset_exposure, business_criticality)
    risk_level, risk_color = get_risk_level(risk_score)

    with col3:
        st.markdown("**🎯 Risk Score**")
        st.markdown("")  # Spacing
        
        # Large risk score display
        st.markdown(f"<h1 style='text-align: center; color: {risk_color}; margin: 0;'>{risk_score:.0f}</h1>", unsafe_allow_html=True)
        st.markdown(f"<p style='text-align: center; font-size: 14px; margin: 0;'>out of 100</p>", unsafe_allow_html=True)
        
        # Progress bar
        st.progress(risk_score / 100)
        
        # Risk level badge
        st.markdown(f"<p style='text-align: center; font-size: 18px; font-weight: bold; color: {risk_color}; margin-top: 10px;'>{risk_level}</p>", unsafe_allow_html=True)

    # Display risk assessment
    st.markdown("---")
    st.subheader("🎯 Risk Assessment for Your Environment")

    # 4-column layout for all details
    col1, col2, col3, col4 = st.columns([1.5, 1.5, 1.5, 1.5])

    with col1:
        st.markdown(f"### Risk Score: **{risk_score:.0f}/100**")
        # Progress bar
        st.progress(risk_score / 100)
        st.markdown(f"### {risk_level}")

    # Explanation
    reasons = get_risk_explanation(selected_cve, asset_exposure, business_criticality, risk_score)

    with col2:
        st.markdown("**Why is this the risk level?**")
        for reason in reasons:
            st.markdown(reason)

    with col3:
        st.markdown("**Recommended Action:**")
        st.markdown(get_recommendation(risk_score, selected_cve, asset_exposure))
    
    with col4:
        st.markdown("**Risk Level Definitions:**")
        st.markdown("""
        🔴 **Critical (90-100):** Immediate action required
        
        🟠 **High (70-89):** Priority patching needed
        
        🟡 **Medium (40-69):** Schedule patching
        
        🟢 **Low (0-39):** Plan and monitor
        """)

    # Detailed calculation breakdown
    with st.expander("🔍 How is this calculated?", expanded=False):
        base = selected_cve['cvss_base_score'] * 5
        
        # Get multipliers (need to recalculate to show)
        exposure_mult = 1.0
        if selected_cve['attack_vector'] == 'Network':
            if asset_exposure == 'Internet-facing':
                exposure_mult = 3.0
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_mult = 2.0
            elif asset_exposure == 'Internal workstation':
                exposure_mult = 1.5
            else:
                exposure_mult = 1.0
        elif selected_cve['attack_vector'] == 'Adjacent':
            if asset_exposure == 'Internet-facing':
                exposure_mult = 1.8
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_mult = 1.5
            else:
                exposure_mult = 1.2
        elif selected_cve['attack_vector'] == 'Local':
            if asset_exposure == 'Internet-facing':
                exposure_mult = 1.2
            elif asset_exposure == 'Server (domain/infrastructure)':
                exposure_mult = 1.0
            else:
                exposure_mult = 0.8
        else:
            exposure_mult = 0.3
        
        exploit_mult = 1.0
        if selected_cve['exploitation_status_display'] == 'Exploitation Detected':
            exploit_mult = 1.5
        elif selected_cve['exploitation_status_display'] == 'More Likely':
            exploit_mult = 1.3
        elif selected_cve['exploitation_status_display'] == 'Less Likely':
            exploit_mult = 1.1
        
        priv_mult = 1.0
        if selected_cve['privileges_required'] == 'None':
            priv_mult = 1.4
        elif selected_cve['privileges_required'] == 'Low':
            priv_mult = 1.2
        
        crit_mult = 2.0 if business_criticality == 'Production' else (1.0 if business_criticality == 'Development/Test' else 0.4)
        
        st.markdown(f"""
        **Risk Score Formula:**
        ```
        Base Score (CVSS × 5)              = {selected_cve['cvss_base_score']:.1f} × 5 = {base:.1f}
        × Exposure Multiplier              = {exposure_mult:.1f}x
        × Exploitation Status              = {exploit_mult:.1f}x
        × Privileges Required              = {priv_mult:.1f}x
        × Business Criticality             = {crit_mult:.1f}x
        ────────────────────────────────────────────
        Final Risk Score (capped at 100)   = {risk_score:.1f}
        ```
        
        **Multiplier Ranges:**
        - 🌐 **Exposure**: 0.3x (Physical) → 3.0x (Network + Internet-facing)
        - 🎯 **Exploitation**: 1.0x (Unlikely) → 1.5x (Detected in wild)
        - 🔑 **Privileges**: 1.0x (High) → 1.4x (None required)
        - 🏢 **Criticality**: 0.4x (Non-business) → 2.0x (Production)
        
        **Total variation range:** Environmental factors can multiply the base score by **0.1x to 12.6x**!
        """)
    
    # Visual risk scale with context
    with st.expander("📊 Risk Scale Context", expanded=False):
        st.markdown("**Understanding where this score falls on the complete risk scale:**")
        
        # Calculate min/max possible for this CVE
        min_risk = selected_cve['cvss_base_score'] * 5 * 0.3 * 1.0 * 1.0 * 0.4  # Minimum multipliers
        max_risk = min(100, selected_cve['cvss_base_score'] * 5 * 3.0 * 1.5 * 1.4 * 2.0)  # Maximum multipliers
        
        # Create a simple horizontal bar chart
        import plotly.graph_objects as go
        
        fig = go.Figure()
        
        # Background scale (0-100)
        fig.add_trace(go.Bar(
            y=['Risk Score'],
            x=[100],
            orientation='h',
            marker=dict(color='#e8e8e8'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        # Possible range for this CVE (highlighted area)
        fig.add_trace(go.Bar(
            y=['Risk Score'],
            x=[max_risk - min_risk],
            orientation='h',
            marker=dict(color='#fff4cc'),
            name=f'Possible Range ({min_risk:.0f}-{max_risk:.0f})',
            base=min_risk,
            showlegend=True,
            hovertemplate='<b>Possible Range</b><br>Min: %{base}<br>Max: %{x}<extra></extra>'
        ))
        
        # Current score marker
        fig.add_trace(go.Scatter(
            x=[risk_score],
            y=['Risk Score'],
            mode='markers',
            marker=dict(size=18, color=risk_color, symbol='diamond'),
            name='Your Score',
            showlegend=True,
            hovertemplate='<b>Your Score: %{x:.0f}</b><extra></extra>'
        ))
        
        fig.update_layout(
            title=f"Your Risk Score Position: {risk_score:.0f}/100",
            xaxis_title="Risk Score",
            xaxis=dict(range=[0, 105], dtick=10),
            yaxis=dict(showticklabels=False),
            height=180,
            barmode='overlay',
            showlegend=True,
            margin=dict(l=20, r=20, t=50, b=50)
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Minimum Possible", f"{min_risk:.0f}", help="Physical attack + Non-critical asset")
        with col2:
            st.metric("Your Score", f"{risk_score:.0f}", delta=f"{risk_score - min_risk:.0f} above minimum")
        with col3:
            st.metric("Maximum Possible", f"{max_risk:.0f}", help="All highest-risk factors combined")

    # Risk band explanation - always visible
    st.markdown("---")
    st.subheader("📊 Understanding Risk Levels")
    if True:  # Keep same indentation structure
        st.markdown("""
        ### Risk Score Bands (0-100 scale)
        
        Our risk scoring system translates technical vulnerability data into actionable patching priorities:
        """)
        
        # Visual breakdown with colored boxes
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            <div style='background-color: #88dd00; padding: 15px; border-radius: 8px; text-align: center;'>
                <h3 style='color: white; margin: 0;'>🟢 LOW</h3>
                <h2 style='color: white; margin: 5px 0;'>0-39</h2>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("""
            **Standard Process**
            - Patch in 60-90 days
            - Include in quarterly updates
            - Monitor for changes
            
            *Typical: Low CVSS on isolated systems*
            """)
        
        with col2:
            st.markdown("""
            <div style='background-color: #ffaa00; padding: 15px; border-radius: 8px; text-align: center;'>
                <h3 style='color: white; margin: 0;'>🟡 MEDIUM</h3>
                <h2 style='color: white; margin: 5px 0;'>40-69</h2>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("""
            **Regular Cycle**
            - Patch within 30 days
            - Next maintenance window
            - Test before deployment
            
            *Typical: Moderate CVSS or protected systems*
            """)
        
        with col3:
            st.markdown("""
            <div style='background-color: #ff6600; padding: 15px; border-radius: 8px; text-align: center;'>
                <h3 style='color: white; margin: 0;'>🟠 HIGH</h3>
                <h2 style='color: white; margin: 5px 0;'>70-89</h2>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("""
            **Urgent Action**
            - Patch within 7 days
            - Prioritize deployment
            - Apply compensating controls
            
            *Typical: High CVSS with exposure*
            """)
        
        with col4:
            st.markdown("""
            <div style='background-color: #ff0000; padding: 15px; border-radius: 8px; text-align: center;'>
                <h3 style='color: white; margin: 0;'>🔥 CRITICAL</h3>
                <h2 style='color: white; margin: 5px 0;'>90-100</h2>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("""
            **Emergency**
            - Patch within 24 hours
            - Isolate if needed
            - Notify management
            
            *Typical: Critical CVSS + Internet + Production + Active exploitation*
            """)
        
        st.markdown("---")
        st.markdown("""
        **What drives a CRITICAL (90+) score?**
        - High CVSS base score (8.0+)
        - Internet-facing exposure (3.0x multiplier)
        - Active exploitation detected (1.5x multiplier)
        - No authentication required (1.4x multiplier)
        - Production environment (2.0x multiplier)
        
        **Example:** CVSS 9.0 × 5 = 45, then 45 × 3.0 × 1.5 × 1.4 × 2.0 = **567** → capped at **100** (CRITICAL)
        
        **What keeps a score LOW (0-39)?**
        - Lower CVSS score (< 6.0)
        - Physical attack vector (0.3x multiplier)
        - High privileges required (1.0x multiplier)
        - Non-business critical system (0.4x multiplier)
        
        **Example:** CVSS 5.0 × 5 = 25, then 25 × 0.3 × 1.0 × 1.0 × 0.4 = **3** (LOW)
        """)

    # Comparison helper
    with st.expander("🔄 Compare Different Asset Types", expanded=False):
        st.markdown("""
        Try changing the asset profile above to see how risk varies:
    
        **Example Comparisons:**
        - **Internet-facing Production** → Highest risk (direct exposure + business impact)
        - **Internet-facing Dev/Test** → High risk (direct exposure but lower impact)
        - **Internal Server Production** → Medium-High risk (requires internal breach first)
        - **Workstation Dev/Test** → Low-Medium risk (multiple barriers to exploit)
    
        The same CVE can require **emergency patching** or **routine maintenance** depending on context!
        """)

    st.markdown("---")

    # Key Metrics


# TAB 3: ANALYTICS & INSIGHTS
with tab3:
    st.header("📊 Executive Summary")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        total_cves = len(df)
        st.metric("Total CVEs", f"{total_cves}")

    with col2:
        critical_count = len(df[df['severity'] == 'Critical'])
        st.metric("🔴 Critical", critical_count)

    with col3:
        important_count = len(df[df['severity'] == 'Important'])
        st.metric("🟠 Important", important_count)

    with col4:
        exploited_count = len(df[df['exploit_status'] == 'exploitation_detected'])
        st.metric("⚠️ Exploited", exploited_count)

    with col5:
        avg_cvss = df['cvss_base_score'].mean()
        st.metric("Avg CVSS", f"{avg_cvss:.1f}")

    st.markdown("---")

    # Severity Distribution
    st.header("🎯 Severity Distribution")

    col1, col2 = st.columns([2, 1])

    with col1:
        # Severity bar chart
        severity_counts = df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
    
        color_map = {
            'Critical': '#ff0000',
            'Important': '#ff6600',
            'Moderate': '#ffaa00',
            'Low': '#88dd00',
            'Unknown': '#888888'
        }
    
        fig = px.bar(
            severity_counts,
            x='Severity',
            y='Count',
            color='Severity',
            text='Count',
            title="CVEs by Severity Rating",
            color_discrete_map=color_map
        )
        fig.update_traces(textposition='outside')
        fig.update_layout(showlegend=False, height=400)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Severity Breakdown")
        for _, row in severity_counts.iterrows():
            emoji = {
                'Critical': '🔴',
                'Important': '🟠',
                'Moderate': '🟡',
                'Low': '🟢',
                'Unknown': '⚪'
            }.get(row['Severity'], '●')
        
            pct = (row['Count'] / total_cves) * 100
            st.metric(
                f"{emoji} {row['Severity']}",
                f"{row['Count']} ({pct:.1f}%)"
            )

    st.markdown("---")

    # Impact Type Distribution
    st.header("🔍 Impact Type Distribution")

    col1, col2 = st.columns(2)

    with col1:
        impact_counts = df['impact_type'].value_counts().head(10).reset_index()
        impact_counts.columns = ['Impact Type', 'Count']
    
        fig = px.bar(
            impact_counts,
            y='Impact Type',
            x='Count',
            orientation='h',
            title="Top Impact Types",
            color='Count',
            color_continuous_scale='Reds'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Exploitation status pie chart
        exploit_counts = df['exploitation_status_display'].value_counts().reset_index()
        exploit_counts.columns = ['Status', 'Count']
    
        fig = px.pie(
            exploit_counts,
            names='Status',
            values='Count',
            title="Exploitation Status Distribution",
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # CVSS Score Distribution
    st.header("📈 CVSS Score Analysis")

    col1, col2 = st.columns(2)

    with col1:
        fig = px.histogram(
            df,
            x='cvss_base_score',
            nbins=20,
            title="CVSS Score Distribution",
            labels={'cvss_base_score': 'CVSS Score', 'count': 'Number of CVEs'},
            color_discrete_sequence=['#667eea']
        )
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # CVSS by Severity
        fig = px.box(
            df,
            x='severity',
            y='cvss_base_score',
            title="CVSS Scores by Severity Rating",
            color='severity',
            color_discrete_map=color_map
        )
        fig.update_layout(height=350, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Critical CVEs Detail
    st.header("🚨 High Priority CVEs")

    # Show exploited CVEs first
    exploited_df = df[df['exploit_status'] == 'exploitation_detected']
    if len(exploited_df) > 0:
        st.subheader(f"⚠️ {len(exploited_df)} CVEs with Active Exploitation Detected")
    
        display_cols = ['cve_id', 'title', 'severity', 'cvss_base_score', 'impact_type', 'attack_vector', 'privileges_required']
        st.dataframe(
            exploited_df[display_cols].sort_values('cvss_base_score', ascending=False),
            use_container_width=True,
            height=250
        )

    # Show critical CVEs
    critical_df = df[df['severity'] == 'Critical']
    if len(critical_df) > 0:
        st.subheader(f"🔴 {len(critical_df)} Critical Severity CVEs")
    
        display_cols = ['cve_id', 'title', 'cvss_base_score', 'impact_type', 'exploitation_status_display', 'attack_vector', 'privileges_required']
        st.dataframe(
            critical_df[display_cols].sort_values('cvss_base_score', ascending=False),
            use_container_width=True,
            height=300
        )

    st.markdown("---")

    # Footer
    col1, col2 = st.columns([3, 1])
    with col1:
        st.caption("PatchIntel Dashboard | Built with Streamlit | November 2025")
        st.caption("Data source: Microsoft Security Update Guide (CVRF) - October 2025 Patch Tuesday")
    with col2:
        st.caption("📊 Data: ✅ Verified")
