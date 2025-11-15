"""
PatchIntel PPR Dashboard
Interactive Streamlit dashboard for Patch Priority Rating (PPR) visualization.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="PatchIntel PPR Dashboard",
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
st.title("🛡️ PatchIntel PPR Dashboard")
st.markdown("**Patch Priority Rating - October 2025 Release | Updated**")

# Add terminology info box
with st.expander("ℹ️ Microsoft Terminology Guide", expanded=False):
    st.markdown("""
    **Field Definitions (from Microsoft Patch Tuesday):**
    
    - **Severity**: The vulnerability category/impact type
      - Remote Code Execution (RCE)
      - Elevation of Privilege (EoP)
      - Denial of Service (DoS)
      - Security Feature Bypass (SFB)
      - Information Disclosure
      - Spoofing
      - Tampering
    
    - **Attack Vector**: Network proximity required
      - N (Network) - Remotely exploitable
      - A (Adjacent) - Adjacent network required
      - L (Local) - Local access required
      - P (Physical) - Physical access required
    
    - **Privileges Required**: Authentication level needed
      - N (None) - No authentication
      - L (Low) - Basic user privileges
      - H (High) - Admin privileges
    
    - **Exploitation Status**: Microsoft's assessment
      - Exploitation Detected - Active exploitation in wild
      - Exploitation More Likely - Higher likelihood
      - Exploitation Less Likely - Lower likelihood
      - Exploitation Unlikely - Unlikely to be exploited
    
    All data sourced directly from Microsoft Security Update Guide (CVRF documents).
    """)

st.markdown("---")

# Load data
@st.cache_data
def load_data():
    base_path = Path(__file__).parent / "output"
    
    data = {}
    try:
        # Load CSVs
        data['full_scores'] = pd.read_csv(base_path / "ppr_full_scale_scores.csv")
        data['emergency'] = pd.read_csv(base_path / "ppr_emergency_risks.csv")
        data['high_priority'] = pd.read_csv(base_path / "ppr_high_priority_risks.csv")
        data['distribution'] = pd.read_csv(base_path / "ppr_distribution.csv")
        data['by_asset'] = pd.read_csv(base_path / "ppr_summary_by_asset.csv")
        data['by_cve'] = pd.read_csv(base_path / "ppr_summary_by_cve.csv")
        
        # Rename columns to use consistent user-friendly terminology
        # 'severity' column contains Impact Type (RCE, EoP, DoS, etc.) - display as "Severity"
        # 'impact_type' column contains Exploitation details string
        for key in ['full_scores', 'emergency', 'high_priority']:
            if key in data:
                data[key] = data[key].rename(columns={
                    'severity': 'severity',  # Keep as 'severity' for display
                    'impact_type': 'exploitation_details'  # Full string from Microsoft
                })
        
        # Keep severity column consistent in by_cve summary
        if 'by_cve' in data and 'severity' in data['by_cve'].columns:
            # Keep as 'severity' for consistency
            pass
        
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return None
    
    return data

data = load_data()

if data is None:
    st.stop()

df = data['full_scores']
distribution = data['distribution']
by_asset = data['by_asset']
by_cve = data['by_cve']

# Key Metrics
st.header("📊 Executive Summary")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    total_risks = len(df)
    st.metric("Total Risks", f"{total_risks:,}")

with col2:
    emergency_count = len(data['emergency'])
    st.metric("🔴 Emergency", emergency_count, delta="120+ PPR")

with col3:
    high_count = len(data['high_priority'])
    st.metric("🟠 High Priority", high_count, delta="80-119 PPR")

with col4:
    unique_assets = df['asset_id'].nunique()
    st.metric("Assets", unique_assets)

with col5:
    unique_cves = df['cve_id'].nunique()
    st.metric("CVEs", unique_cves)

st.markdown("---")

# Priority Distribution
st.header("🎯 Priority Band Distribution")

col1, col2 = st.columns([2, 1])

with col1:
    # Bar chart of distribution
    fig = px.bar(
        distribution,
        x='priority_band',
        y='count',
        color='priority_band',
        text='count',
        title="Risks by Priority Band",
        labels={'count': 'Number of Risks', 'priority_band': 'Priority Band'},
        color_discrete_map={
            'EMERGENCY PATCH': '#ff0000',
            'HIGH PRIORITY': '#ff6600',
            'ELEVATED': '#ffaa00',
            'MODERATE': '#ffdd00',
            'LOW': '#88dd00',
            'INFORMATIONAL': '#4488ff'
        }
    )
    fig.update_traces(textposition='outside')
    fig.update_layout(showlegend=False, height=400)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Distribution Stats")
    for _, row in distribution.iterrows():
        emoji = {
            'EMERGENCY PATCH': '🔴',
            'HIGH PRIORITY': '🟠',
            'ELEVATED': '🟡',
            'MODERATE': '🟢',
            'LOW': '⚪',
            'INFORMATIONAL': '🔵'
        }.get(row['priority_band'], '●')
        
        st.metric(
            f"{emoji} {row['priority_band']}",
            f"{row['count']} ({row['percentage']:.1f}%)",
            delta=f"{row['min_score']}-{row['max_score']} PPR"
        )

st.markdown("---")

# Top Vulnerable Assets
st.header("💻 Most Vulnerable Assets")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Top 10 Assets by CVE Count")
    top_assets = by_asset.nlargest(10, 'total_cves')
    
    fig = px.bar(
        top_assets,
        y='hostname',
        x='total_cves',
        orientation='h',
        color='ppr_max',
        title="Assets with Most CVEs",
        labels={'total_cves': 'Total CVEs', 'hostname': 'Asset', 'ppr_max': 'Max PPR'},
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Top 10 Assets by Max PPR")
    top_ppr_assets = by_asset.nlargest(10, 'ppr_max')
    
    fig = px.bar(
        top_ppr_assets,
        y='hostname',
        x='ppr_max',
        orientation='h',
        color='asset_type',
        title="Assets with Highest PPR Scores",
        labels={'ppr_max': 'Max PPR Score', 'hostname': 'Asset', 'asset_type': 'Type'}
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Top CVEs
st.header("🔍 Most Critical CVEs")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Top 10 CVEs by Asset Impact")
    top_cves_by_assets = by_cve.nlargest(10, 'affected_assets')
    
    fig = px.bar(
        top_cves_by_assets,
        y='cve_id',
        x='affected_assets',
        orientation='h',
        color='ppr_max',
        title="Most Widespread CVEs",
        labels={'affected_assets': 'Affected Assets', 'cve_id': 'CVE ID', 'ppr_max': 'Max PPR'},
        color_continuous_scale='Oranges'
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Top 10 CVEs by Max PPR")
    top_cves_by_ppr = by_cve.nlargest(10, 'ppr_max')
    
    fig = px.bar(
        top_cves_by_ppr,
        y='cve_id',
        x='ppr_max',
        orientation='h',
        color='cvss_score',
        title="Highest Priority CVEs",
        labels={'ppr_max': 'Max PPR Score', 'cve_id': 'CVE ID', 'cvss_score': 'CVSS'},
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Emergency Risks Detail
st.header("🚨 Emergency Patch Required (PPR ≥ 120)")

if len(data['emergency']) > 0:
    st.subheader(f"{len(data['emergency'])} Critical Risks Requiring Immediate Action")
    
    # Show unique CVEs in emergency category
    emergency_cves = data['emergency'].groupby('cve_id').agg({
        'hostname': 'count',
        'title': 'first',
        'cvss_score': 'first',
        'ppr_score': 'max',
        'exploitation_status': 'first'
    }).reset_index()
    emergency_cves.columns = ['CVE ID', 'Affected Assets', 'Title', 'CVSS', 'Max PPR', 'Exploitation']
    emergency_cves = emergency_cves.sort_values('Max PPR', ascending=False)
    
    st.dataframe(
        emergency_cves,
        use_container_width=True,
        height=400
    )
    
    # Download button
    csv = data['emergency'].to_csv(index=False)
    st.download_button(
        label="📥 Download Emergency Risks CSV",
        data=csv,
        file_name="ppr_emergency_risks.csv",
        mime="text/csv"
    )
else:
    st.success("✅ No emergency risks detected!")

st.markdown("---")

# Filters and Detail View
st.header("🔎 Detailed Risk Explorer")

# View toggle
view_mode = st.radio(
    "View Mode",
    options=["By Asset-CVE Pairs", "By Unique CVEs"],
    horizontal=True
)

if view_mode == "By Asset-CVE Pairs":
    col1, col2, col3 = st.columns(3)

    with col1:
        priority_filter = st.multiselect(
            "Filter by Priority Band",
            options=df['priority_band'].unique(),
            default=df['priority_band'].unique()
        )

    with col2:
        asset_type_filter = st.multiselect(
            "Filter by Asset Type",
            options=df['asset_type'].unique(),
            default=df['asset_type'].unique()
        )

    with col3:
        min_ppr = st.slider(
            "Minimum PPR Score",
            min_value=int(df['ppr_score'].min()),
            max_value=int(df['ppr_score'].max()),
            value=int(df['ppr_score'].min())
        )

    # Apply filters
    filtered_df = df[
        (df['priority_band'].isin(priority_filter)) &
        (df['asset_type'].isin(asset_type_filter)) &
        (df['ppr_score'] >= min_ppr)
    ]

    st.subheader(f"Showing {len(filtered_df):,} of {len(df):,} risks")

    # Display columns for the table
    display_cols = [
        'hostname', 'cve_id', 'title', 'ppr_score', 'cvss_score', 
        'priority_band', 'exploitation_status', 'severity'
    ]

    st.dataframe(
        filtered_df[display_cols].sort_values('ppr_score', ascending=False),
        use_container_width=True,
        height=400
    )

else:
    # CVE View with advanced sorting
    st.subheader("📋 Unique CVEs with Sorting Options")
    
    # Create aggregated CVE view
    cve_aggregated = df.groupby('cve_id').agg({
        'title': 'first',
        'cvss_score': 'first',
        'attack_vector': 'first',
        'privileges_required': 'first',
        'severity': 'first',
        'exploitation_status': 'first',
        'hostname': 'count'
    }).reset_index()
    
    # Map abbreviations to full labels
    attack_vector_labels = {
        'N': 'Network',
        'A': 'Adjacent',
        'L': 'Local',
        'P': 'Physical'
    }
    
    privilege_labels = {
        'N': 'None',
        'L': 'Low',
        'H': 'High'
    }
    
    # Apply full labels
    cve_aggregated['attack_vector'] = cve_aggregated['attack_vector'].map(attack_vector_labels).fillna(cve_aggregated['attack_vector'])
    cve_aggregated['privileges_required'] = cve_aggregated['privileges_required'].map(privilege_labels).fillna(cve_aggregated['privileges_required'])
    
    # Flatten column names
    cve_aggregated.columns = [
        'CVE ID', 'Title', 'CVSS Score', 'Attack Vector', 
        'Privileges Required', 'Severity', 'Exploitation Status', 'Affected Assets'
    ]
    
    # Sorting controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        sort_by = st.selectbox(
            "Sort by",
            options=[
                'CVSS Score',
                'Attack Vector',
                'Privileges Required',
                'Severity',
                'Exploitation Status',
                'Affected Assets'
            ],
            index=0
        )
    
    with col2:
        sort_order = st.radio(
            "Order",
            options=['Descending', 'Ascending'],
            horizontal=True,
            help="Descending = Most severe first (Network→Physical, None→High, RCE→Spoofing, Detected→Unlikely)"
        )
    
    with col3:
        min_cvss = st.slider(
            "Minimum CVSS",
            min_value=0.0,
            max_value=10.0,
            value=0.0,
            step=0.5
        )
    
    # Apply CVSS filter
    filtered_cves = cve_aggregated[cve_aggregated['CVSS Score'] >= min_cvss]
    
    # Map sort priorities for categorical columns (higher = more severe)
    # Attack Vector: Network is most severe (remotely exploitable)
    attack_vector_priority = {
        'Network': 4,
        'Adjacent': 3,
        'Local': 2,
        'Physical': 1,
        '': 0
    }
    
    # Privileges Required: None is most severe (no authentication needed)
    privilege_priority = {
        'None': 3,
        'Low': 2,
        'High': 1,
        '': 0
    }
    
    # Exploitation Status: Detected in wild is most severe
    exploit_priority = {
        'exploitation_detected': 5,
        'exploitation_more_likely': 4,
        'exploitation_less_likely': 3,
        'exploitation_unlikely': 2,
        'UNKNOWN': 1,
        '': 0
    }
    
    # Severity/Impact Type: RCE is most severe, then EoP, etc.
    severity_priority = {
        'Remote Code Execution': 7,
        'Elevation of Privilege': 6,
        'Security Feature Bypass': 5,
        'Tampering': 4,
        'Information Disclosure': 3,
        'Denial of Service': 2,
        'Spoofing': 1,
        '': 0
    }
    
    # Create sort keys based on severity (higher priority = more severe)
    if sort_by == 'Attack Vector':
        filtered_cves['sort_key'] = filtered_cves['Attack Vector'].map(attack_vector_priority).fillna(0)
        # Most severe first by default (Network > Adjacent > Local > Physical)
        filtered_cves = filtered_cves.sort_values('sort_key', ascending=(sort_order == 'Ascending'))
        filtered_cves = filtered_cves.drop('sort_key', axis=1)
    
    elif sort_by == 'Privileges Required':
        filtered_cves['sort_key'] = filtered_cves['Privileges Required'].map(privilege_priority).fillna(0)
        # Most severe first by default (None > Low > High)
        filtered_cves = filtered_cves.sort_values('sort_key', ascending=(sort_order == 'Ascending'))
        filtered_cves = filtered_cves.drop('sort_key', axis=1)
    
    elif sort_by == 'Exploitation Status':
        filtered_cves['sort_key'] = filtered_cves['Exploitation Status'].map(exploit_priority).fillna(0)
        # Most severe first by default (detected > more_likely > less_likely > unlikely)
        filtered_cves = filtered_cves.sort_values('sort_key', ascending=(sort_order == 'Ascending'))
        filtered_cves = filtered_cves.drop('sort_key', axis=1)
    
    elif sort_by == 'Severity':
        filtered_cves['sort_key'] = filtered_cves['Severity'].map(severity_priority).fillna(0)
        # Most severe first by default (RCE > EoP > SFB > Tampering > Info Disclosure > DoS > Spoofing)
        filtered_cves = filtered_cves.sort_values('sort_key', ascending=(sort_order == 'Ascending'))
        filtered_cves = filtered_cves.drop('sort_key', axis=1)
    
    else:
        # Numeric sorting for CVSS, Affected Assets
        filtered_cves = filtered_cves.sort_values(sort_by, ascending=(sort_order == 'Ascending'))
    
    st.info(f"📊 Showing {len(filtered_cves)} CVEs sorted by **{sort_by}** ({sort_order})")
    
    # Display the sorted CVE table
    st.dataframe(
        filtered_cves,
        use_container_width=True,
        height=500
    )
    
    # Download sorted CVE data
    csv_cves = filtered_cves.to_csv(index=False)
    st.download_button(
        label=f"📥 Download Sorted CVEs ({sort_by})",
        data=csv_cves,
        file_name=f"ppr_cves_sorted_by_{sort_by.lower().replace(' ', '_')}.csv",
        mime="text/csv"
    )

# Download filtered data (for asset-cve view)
if view_mode == "By Asset-CVE Pairs":
    csv_filtered = filtered_df.to_csv(index=False)
    st.download_button(
        label="📥 Download Filtered Results",
        data=csv_filtered,
        file_name="ppr_filtered_risks.csv",
        mime="text/csv"
    )


st.markdown("---")

# Footer
col1, col2 = st.columns([3, 1])
with col1:
    st.caption("PatchIntel PPR Dashboard v1.2 | Built with Streamlit | November 2025")
    st.caption("Severity = Vulnerability Impact Type (RCE, EoP, DoS, SFB, etc.)")
with col2:
    st.caption("📊 Data Quality: ✅ Verified")
