"""
Script to reorganize dashboard.py into 3 tabs
"""

# Read the original dashboard
with open('dashboard_backup.py', 'r') as f:
    lines = f.readlines()

# Section boundaries
tab_insert_line = 149  # After "if df is None: st.stop()"
cve_explorer_start = 150
risk_calc_start = 308
analytics_start = 579

# Build new file
new_lines = []

# Part 1: Everything before tabs (header, imports, data loading)
new_lines.extend(lines[:tab_insert_line])

# Insert tab creation
new_lines.append('\n# Create tabs\n')
new_lines.append('tab1, tab2, tab3 = st.tabs(["📊 CVE Explorer", "🎯 Risk Calculator", "📈 Analytics & Insights"])\n')
new_lines.append('\n')

# Part 2: TAB 1 - CVE Explorer (lines 150-307)
new_lines.append('# TAB 1: CVE EXPLORER\n')
new_lines.append('with tab1:\n')
for line in lines[cve_explorer_start:risk_calc_start]:
    # Skip the old section headers and dividers right before Risk Calculator
    if line.strip() == 'st.markdown("---")' and lines[lines.index(line) + 1] == lines[risk_calc_start]:
        continue
    # Add indentation
    if line.strip():  # Don't indent empty lines
        new_lines.append('    ' + line)
    else:
        new_lines.append(line)

# Part 3: TAB 2 - Risk Calculator (lines 308-578)
new_lines.append('\n# TAB 2: RISK CALCULATOR\n')
new_lines.append('with tab2:\n')
for line in lines[risk_calc_start:analytics_start]:
    # Skip dividers
    if line.strip() == 'st.markdown("---")' and lines.index(line) >= analytics_start - 3:
        continue
    # Add indentation
    if line.strip():
        new_lines.append('    ' + line)
    else:
        new_lines.append(line)

# Part 4: TAB 3 - Analytics (lines 579 to end)
new_lines.append('\n# TAB 3: ANALYTICS & INSIGHTS\n')
new_lines.append('with tab3:\n')
for line in lines[analytics_start:]:
    # Add indentation
    if line.strip():
        new_lines.append('    ' + line)
    else:
        new_lines.append(line)

# Write new file
with open('dashboard.py', 'w') as f:
    f.writelines(new_lines)

print("✅ Dashboard reorganized successfully!")
print(f"  - Tab 1 (CVE Explorer): {risk_calc_start - cve_explorer_start} lines")
print(f"  - Tab 2 (Risk Calculator): {analytics_start - risk_calc_start} lines") 
print(f"  - Tab 3 (Analytics): {len(lines) - analytics_start} lines")

