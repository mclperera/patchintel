"""
PatchIntel Risk Dashboard
Simple Streamlit dashboard for viewing and configuring risk scores.
"""

import streamlit as st
import pandas as pd
from pathlib import Path
import sys

# Add risk-engine src to path for imports
risk_engine_src = Path(__file__).parent.parent / "risk-engine" / "src"
sys.path.insert(0, str(risk_engine_src))

from config_loader import RiskScoringConfig
from calculator import RiskCalculator

# Page configuration
st.set_page_config(
    page_title="PatchIntel Risk Dashboard",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Title
st.title("🎯 PatchIntel Risk Dashboard")
st.markdown("**Vulnerability Risk Scoring & Configuration**")

# Simple test - load and show basic stats
st.header("📊 Quick Stats")

# Try to load the risk scores
risk_scores_path = Path(__file__).parent.parent / "output" / "risk_scores.csv"

if risk_scores_path.exists():
    df = pd.read_csv(risk_scores_path)
    
    # Initialize session state for configuration if not exists
    if 'config_applied' not in st.session_state:
        st.session_state.config_applied = False
        st.session_state.original_df = df.copy()
    
    # Recalculate FIRST if configuration was applied
    if st.session_state.config_applied and 'config_values' in st.session_state:
        config_vals = st.session_state.config_values
        
        # Show a banner that recalculation is active
        st.info("🔄 **Custom Configuration Active** - Displaying recalculated risk scores")
        
        # Create custom config with scaled multipliers
        custom_config_dict = {
            'name': 'Dashboard Custom Configuration',
            'version': '1.0',
            'cvss_base_score': {
                'use_as_base': True,
                'missing_score_default': config_vals['default_cvss'],
                'scale_factor': 10
            },
            'business_criticality_multiplier': {
                'level_1_critical': 2.0 * config_vals['business_criticality_scale'],
                'level_2_high': 1.5 * config_vals['business_criticality_scale'],
                'level_3_medium': 1.0 * config_vals['business_criticality_scale'],
                'level_4_low': 0.5 * config_vals['business_criticality_scale']
            },
            'exploit_status_multiplier': {
                'exploited_in_wild': 3.0 * config_vals['exploit_scale'],
                'publicly_disclosed': 2.0 * config_vals['exploit_scale'],
                'exploitation_unlikely': 0.5 * config_vals['exploit_scale'],
                'default': 1.0 * config_vals['exploit_scale']
            },
            'severity_type_multiplier': {
                'Remote Code Execution': 2.0 * config_vals['severity_scale'],
                'Elevation of Privilege': 1.5 * config_vals['severity_scale'],
                'Security Feature Bypass': 1.2 * config_vals['severity_scale'],
                'Denial of Service': 1.0 * config_vals['severity_scale'],
                'Tampering': 1.1 * config_vals['severity_scale'],
                'Spoofing': 0.9 * config_vals['severity_scale'],
                'Information Disclosure': 0.8 * config_vals['severity_scale']
            },
            'age_multiplier': {
                'days_0_to_7': 1.5 * config_vals['age_scale'],
                'days_8_to_30': 1.3 * config_vals['age_scale'],
                'days_31_to_90': 1.1 * config_vals['age_scale'],
                'days_90_plus': 1.0 * config_vals['age_scale']
            },
            'asset_type_multiplier': {
                'server': 1.3 * config_vals['asset_scale'],
                'laptop': 1.0 * config_vals['asset_scale'],
                'desktop': 0.9 * config_vals['asset_scale'],
                'virtual_machine': 1.2 * config_vals['asset_scale'],
                'container': 1.1 * config_vals['asset_scale']
            },
            'scoring': {
                'cap_maximum': 100,
                'floor_minimum': 0
            },
            'priority_bands': {
                'critical': {'min_score': 90, 'max_score': 100, 'label': 'CRITICAL'},
                'high': {'min_score': 75, 'max_score': 89, 'label': 'HIGH'},
                'elevated': {'min_score': 60, 'max_score': 74, 'label': 'ELEVATED'},
                'medium': {'min_score': 40, 'max_score': 59, 'label': 'MEDIUM'},
                'low': {'min_score': 20, 'max_score': 39, 'label': 'LOW'},
                'informational': {'min_score': 0, 'max_score': 19, 'label': 'INFORMATIONAL'}
            }
        }
        
        custom_config = RiskScoringConfig(custom_config_dict)
        calculator = RiskCalculator(custom_config)
        
        # Get fresh copy of original data and drop old calculated columns
        recalc_df = st.session_state.original_df.copy()
        columns_to_drop = ['risk_score', 'priority_band', 'priority_action', 'priority_sla_hours', 
                          'priority_color', 'cvss_base', 'criticality_mult', 'exploit_mult', 
                          'severity_mult', 'age_mult', 'asset_type_mult', 'age_days']
        recalc_df = recalc_df.drop(columns=[col for col in columns_to_drop if col in recalc_df.columns], errors='ignore')
        
        # Debug: Show what we're passing to calculator
        st.caption(f"🔍 Debug: Recalculating {len(recalc_df)} rows with scales: BC={config_vals['business_criticality_scale']}x, ES={config_vals['exploit_scale']}x, ST={config_vals['severity_scale']}x, Age={config_vals['age_scale']}x, Asset={config_vals['asset_scale']}x")
        
        # Recalculate risk scores
        df = calculator.calculate_bulk(recalc_df)
        
        # Debug: Show sample of recalculated data and compare
        original_critical = st.session_state.original_df[st.session_state.original_df['priority_band'] == 'CRITICAL']['cve_id'].nunique()
        new_critical = df[df['priority_band'] == 'CRITICAL']['cve_id'].nunique()
        st.caption(f"✓ Recalculated: Risk scores now range from {df['risk_score'].min():.2f} to {df['risk_score'].max():.2f} | CRITICAL CVEs: {original_critical} → {new_critical}")
    else:
        st.success("📊 Showing default risk scores from file")
    
    # NOW display metrics with the updated df
    # Display actionable metrics in columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        critical_cves = df[df['priority_band'] == 'CRITICAL']['cve_id'].nunique()
        st.metric("🚨 CRITICAL CVEs", f"{critical_cves}", help="Unique CVEs requiring immediate patching (24h SLA)")
    
    with col2:
        high_cves = df[df['priority_band'] == 'HIGH']['cve_id'].nunique()
        st.metric("🔴 HIGH CVEs", f"{high_cves}", help="Unique CVEs for priority patching (72h SLA)")
    
    with col3:
        assets_critical = df[df['priority_band'] == 'CRITICAL']['asset_id'].nunique()
        st.metric("💻 Critical Assets", f"{assets_critical}", help="Assets with CRITICAL vulnerabilities")
    
    with col4:
        avg_risk = df['risk_score'].mean()
        st.metric("📊 Avg Risk Score", f"{avg_risk:.1f}/100", help="Overall risk posture")
    
    # Remove the duplicate success message that was here before
    
    # Priority Band Heatmap
    st.header("🔥 Risk Priority Heatmap")
    
    # Calculate stats per priority band
    priority_stats = df.groupby('priority_band').agg({
        'asset_id': 'nunique',
        'cve_id': 'nunique',
        'risk_score': ['count', 'mean']
    }).round(2)
    
    # Flatten column names
    priority_stats.columns = ['Unique Assets', 'Unique CVEs', 'Total Risks', 'Avg Risk Score']
    priority_stats = priority_stats.reset_index()
    
    # Define priority order and colors
    priority_order = ['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'INFORMATIONAL']
    priority_colors = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff8800',
        'ELEVATED': '#ffaa00',
        'MEDIUM': '#ffdd00',
        'LOW': '#88dd00',
        'INFORMATIONAL': '#4488ff'
    }
    
    # Sort by priority order
    priority_stats['priority_band'] = pd.Categorical(
        priority_stats['priority_band'], 
        categories=priority_order, 
        ordered=True
    )
    priority_stats = priority_stats.sort_values('priority_band')
    
    # Display as colored metrics
    cols = st.columns(len(priority_stats))
    
    for idx, col in enumerate(cols):
        with col:
            row = priority_stats.iloc[idx]
            band = row['priority_band']
            color = priority_colors.get(band, '#999999')
            
            # Create a styled box
            st.markdown(f"""
                <div style="
                    background-color: {color}22;
                    border-left: 4px solid {color};
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                ">
                    <h4 style="margin:0; color:{color};">{band}</h4>
                    <hr style="margin: 5px 0; border-color: {color}44;">
                    <p style="margin:5px 0;"><b>Assets:</b> {int(row['Unique Assets'])}</p>
                    <p style="margin:5px 0;"><b>CVEs:</b> {int(row['Unique CVEs'])}</p>
                    <p style="margin:5px 0;"><b>Avg Score:</b> {row['Avg Risk Score']:.1f}</p>
                </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Risk Configuration Dials (Collapsible)
    with st.expander("⚙️ Risk Configuration - Adjust Scoring Multipliers", expanded=False):
        st.markdown("**Modify the risk scoring parameters below:**")
        st.info("💡 Adjust the multipliers and click 'Apply Configuration' to recalculate risk scores in real-time.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Business Criticality Multiplier - applies to ALL levels proportionally
            business_criticality_scale = st.slider(
                "Business Criticality Scale",
                min_value=0.5,
                max_value=2.0,
                value=1.0,
                step=0.1,
                help="Scale ALL business criticality multipliers (0.5x = half impact, 2.0x = double impact)",
                key="business_crit_slider"
            )
            
            # Exploit Status Multiplier - scale all exploit multipliers
            exploit_scale = st.slider(
                "Exploit Status Scale",
                min_value=0.5,
                max_value=2.0,
                value=1.0,
                step=0.1,
                help="Scale ALL exploit status multipliers (0.5x = reduce impact, 2.0x = increase impact)",
                key="exploit_slider"
            )
            
            # Severity Type Multiplier - scale all severity multipliers
            severity_scale = st.slider(
                "Severity Type Scale",
                min_value=0.5,
                max_value=2.0,
                value=1.0,
                step=0.1,
                help="Scale ALL severity type multipliers (0.5x = reduce impact, 2.0x = increase impact)",
                key="severity_slider"
            )
        
        with col2:
            # Age/Freshness Multiplier - scale all age multipliers
            age_scale = st.slider(
                "Age/Freshness Scale",
                min_value=0.5,
                max_value=2.0,
                value=1.0,
                step=0.1,
                help="Scale ALL age multipliers (0.5x = reduce recency impact, 2.0x = increase recency impact)",
                key="age_slider"
            )
            
            # Asset Type Multiplier - scale all asset type multipliers
            asset_scale = st.slider(
                "Asset Type Scale",
                min_value=0.5,
                max_value=2.0,
                value=1.0,
                step=0.1,
                help="Scale ALL asset type multipliers (0.5x = reduce impact, 2.0x = increase impact)",
                key="asset_type_slider"
            )
            
            # Default CVSS Score
            default_cvss = st.slider(
                "Default CVSS (if missing)",
                min_value=0.0,
                max_value=10.0,
                value=7.5,
                step=0.5,
                help="CVSS score to use when not available (0.0 - 10.0)",
                key="cvss_slider"
            )
        
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
        with col_btn1:
            if st.button("🔄 Apply Configuration", type="primary", use_container_width=True):
                st.session_state.config_applied = True
                st.session_state.config_values = {
                    'business_criticality_scale': business_criticality_scale,
                    'exploit_scale': exploit_scale,
                    'severity_scale': severity_scale,
                    'age_scale': age_scale,
                    'asset_scale': asset_scale,
                    'default_cvss': default_cvss
                }
                st.rerun()
        
        with col_btn2:
            if st.button("↺ Reset to Default", use_container_width=True):
                st.session_state.config_applied = False
                st.session_state.pop('config_values', None)
                st.rerun()
        
        # Show current configuration status
        if st.session_state.config_applied and 'config_values' in st.session_state:
            st.success("✅ Custom configuration active - Scores recalculated")
            with st.expander("📋 Active Configuration Values"):
                config = st.session_state.config_values
                col_a, col_b = st.columns(2)
                with col_a:
                    st.write(f"**Business Criticality Scale:** {config['business_criticality_scale']}x")
                    st.write(f"**Exploit Status Scale:** {config['exploit_scale']}x")
                    st.write(f"**Severity Type Scale:** {config['severity_scale']}x")
                with col_b:
                    st.write(f"**Age/Freshness Scale:** {config['age_scale']}x")
                    st.write(f"**Asset Type Scale:** {config['asset_scale']}x")
                    st.write(f"**Default CVSS:** {config['default_cvss']}")
    
    st.markdown("---")
    
    # Show a sample of the data
    st.subheader("📋 Sample Data (first 10 rows)")
    st.dataframe(
        df[['hostname', 'cve_id', 'risk_score', 'priority_band', 'severity']].head(10),
        use_container_width=True
    )
    
else:
    st.error(f"❌ Risk scores file not found at: {risk_scores_path}")
    st.info("💡 Run the risk calculation first: `python risk-engine/patchintel-risk.py calculate ...`")

st.markdown("---")
st.caption("PatchIntel Dashboard v0.1 | Phase 4 Development")
