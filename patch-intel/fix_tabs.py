#!/usr/bin/env python3
"""
Fix dashboard.py tab indentation issue.
The problem: content after 'with tab2:' is not indented, causing duplication across all tabs.
Solution: Properly indent Tab 2 and Tab 3 content.
"""

def fix_dashboard():
    with open('dashboard.py', 'r') as f:
        lines = f.readlines()
    
    fixed_lines = []
    in_tab2 = False
    in_tab3 = False
    tab1_ended = False
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Tab 1: starts at line 152, ends at line 309
        if line.strip() == "with tab1:":
            fixed_lines.append(line)
            in_tab2 = False
            in_tab3 = False
            continue
        
        # Tab 2: starts at line 310
        if line.strip() == "with tab2:":
            # First, close tab1 if needed
            if not tab1_ended:
                tab1_ended = True
            fixed_lines.append(line)
            in_tab2 = True
            in_tab3 = False
            continue
        
        # Tab 3: should start at "Executive Summary" (line 581)
        if 'st.header("📊 Executive Summary")' in line and in_tab2:
            # Insert tab3 wrapper before this line
            fixed_lines.append('\n# TAB 3: ANALYTICS & INSIGHTS\n')
            fixed_lines.append('with tab3:\n')
            in_tab2 = False
            in_tab3 = True
            # Add the header line with proper indentation
            fixed_lines.append('    ' + line)
            continue
        
        # Indent lines that should be inside tab2 or tab3
        if in_tab2 or in_tab3:
            # Skip empty lines or lines that are already indented
            if line.strip() == '':
                fixed_lines.append(line)
            elif line.startswith('    '):
                # Already indented - keep as is
                fixed_lines.append(line)
            elif line.startswith('#') or line.startswith('def ') or line.startswith('st.') or line.startswith('col') or line.startswith('with ') or line.startswith('if ') or line.startswith('for ') or line.startswith('csv ') or line.startswith('risk_') or line.startswith('high_') or line.startswith('selected_') or line.startswith('severity_') or line.startswith('exploit') or line.startswith('critical_') or line.startswith('    return') or line.startswith('fig ') or 'plt.' in line:
                # These need indentation
                fixed_lines.append('    ' + line)
            else:
                fixed_lines.append(line)
        else:
            # Outside tabs - keep as is
            fixed_lines.append(line)
    
    # Write fixed content
    with open('dashboard_fixed.py', 'w') as f:
        f.writelines(fixed_lines)
    
    print(f"✅ Fixed dashboard written to dashboard_fixed.py")
    print(f"📊 Total lines: {len(fixed_lines)}")
    
    # Show summary
    tab2_start = None
    tab3_start = None
    for i, line in enumerate(fixed_lines):
        if 'with tab2:' in line:
            tab2_start = i + 1
        if 'with tab3:' in line:
            tab3_start = i + 1
    
    print(f"🔹 Tab 2 starts at line: {tab2_start}")
    print(f"🔹 Tab 3 starts at line: {tab3_start}")

if __name__ == '__main__':
    fix_dashboard()
