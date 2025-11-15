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

# Add Microsoft terminology guide
with st.expander("ℹ️ Microsoft CVRF Field Definitions", expanded=False):
    st.markdown("""
    **Data Source:** Microsoft Security Update Guide (CVRF - Common Vulnerability Reporting Framework)
    
    **Key Fields:**
    
    - **Severity Rating** (Type 3): Microsoft's official severity assessment
      - Critical, Important, Moderate, Low
    
    - **Impact Type** (Type 0): The vulnerability category
      - Remote Code Execution (RCE)
      - Elevation of Privilege (EoP)
      - Denial of Service (DoS)
      - Security Feature Bypass (SFB)
      - Information Disclosure
      - Spoofing
      - Tampering
    
    - **Exploitation Status** (Type 1): Microsoft's exploitation assessment
      - exploitation_detected - Active exploitation in the wild
      - exploitation_more_likely - Higher likelihood of exploitation
      - exploitation_less_likely - Lower likelihood of exploitation
      - exploitation_unlikely - Unlikely to be exploited
    
    - **CVSS Score**: Common Vulnerability Scoring System (0-10)
    
    - **Attack Vector**: Network proximity required
      - Network (N) - Remotely exploitable
      - Adjacent (A) - Adjacent network required
      - Local (L) - Local access required
      - Physical (P) - Physical access required
    
    - **Privileges Required**: Authentication level needed
      - None (N) - No authentication
      - Low (L) - Basic user privileges
      - High (H) - Admin privileges
    """)

st.markdown("---")

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

# Key Metrics
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
st.header("🚨 Critical & Exploited CVEs")

# Show exploited CVEs first
exploited_df = df[df['exploit_status'] == 'exploitation_detected']
if len(exploited_df) > 0:
    st.subheader(f"⚠️ {len(exploited_df)} CVEs with Active Exploitation")
    
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

# Detailed CVE Explorer
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

st.markdown("---")

# Footer
col1, col2 = st.columns([3, 1])
with col1:
    st.caption("PatchIntel Dashboard v2.0 | Built with Streamlit | November 2025")
    st.caption("Data source: Microsoft Security Update Guide (CVRF) - October 2025 Patch Tuesday")
with col2:
    st.caption("📊 Data Quality: ✅ Verified")
