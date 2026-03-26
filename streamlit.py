import streamlit as st
import pandas as pd
from fpdf import FPDF
from datetime import datetime
import streamlit.components.v1 as components
import textwrap
import json
import os
import glob

# --- Recommended Actions Mapping ---
recommended_actions = {
    "Public access is allowed due to misconfigured Public Access Block settings.":
        "Update the Public Access Block settings to enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
    "No Public Access Block configuration found.":
        "Implement Public Access Block settings for this bucket, enabling all four block options (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) to prevent unintended public access.",
    "Bucket policy allows public access.":
        "Review and revise the S3 bucket policy to remove or restrict statements that grant public access ('Principal': '*' or 'Principal': {'AWS': '*'}). Apply the principle of least privilege.",
    "Bucket encryption is not enabled.":
        "Enable server-side encryption (e.g., AES-256 or AWS KMS) for the S3 bucket to protect data at rest.",
    "Bucket versioning is not enabled.":
        "Enable bucket versioning to protect against accidental deletions and to maintain file history.",
    "Bucket logging is not enabled.":
        "Enable bucket logging to track access and modifications for audit purposes.",
    "SSH (port 22) publicly accessible":
        "Restrict SSH (port 22) access to only known, trusted IP addresses or ranges. Consider using a VPN or bastion host for more secure access.",
    "RDP (port 3389) publicly accessible":
        "Restrict RDP (port 3389) access to only known, trusted IP addresses or ranges. Consider using a VPN or bastion host for secure remote desktop access.",
    "MySQL (port 3306) publicly accessible":
        "Restrict MySQL (port 3306) access to only application servers that need it. Never expose databases to the public internet.",
    "PostgreSQL (port 5432) publicly accessible":
        "Restrict PostgreSQL (port 5432) access to only application servers that need it. Never expose databases to the public internet.",
    "HTTP (port 80) publicly accessible":
        "If this EC2 instance hosts a web application, ensure it is protected by a Web Application Firewall (WAF) and consider using HTTPS (port 443) with a load balancer. If direct HTTP access is not required, restrict it to specific source IPs or remove the rule.",
    "HTTPS (port 443) publicly accessible - ensure WAF is configured":
        "Verify that a Web Application Firewall (WAF) is configured to protect this endpoint. Ensure proper SSL/TLS certificate configuration.",
    "ICMP (Ping) publicly accessible":
        "Restrict ICMP (Ping) access to specific IP ranges needed for diagnostics. If not essential for monitoring, consider removing public ICMP access to reduce network reconnaissance possibilities.",
    "All traffic (all protocols) publicly accessible":
        "IMMEDIATELY restrict this rule. This is a critical security risk. Update the security group to allow only necessary protocols and ports from specific source IPs.",
    "User does not have MFA enabled.":
        "Enable Multi-Factor Authentication (MFA) on the user account for enhanced security.",
    "User account appears to be inactive (no console or API usage).":
        "Review the account's usage and consider deactivating or removing unused accounts to reduce the attack surface.",
    "RDS instance is publicly accessible.":
        "Disable public accessibility for the RDS instance. Place it in a private subnet and access it only through application servers or a VPN.",
    "RDS instance does not have encryption at rest enabled.":
        "Enable encryption at rest for the RDS instance. Note: This requires creating a new encrypted instance and migrating data.",
    "RDS instance does not have automated backups enabled.":
        "Enable automated backups with an appropriate retention period (recommended: 7-35 days).",
    "RDS instance is not configured for Multi-AZ deployment.":
        "Enable Multi-AZ deployment for high availability and automatic failover capabilities.",
    "No CloudTrail trails configured in this region.":
        "Create a CloudTrail trail to log all API calls and account activity for audit and security monitoring.",
    "CloudTrail is not actively logging.":
        "Enable logging for the CloudTrail trail immediately to ensure all API activity is being recorded.",
    "CloudTrail log file validation is not enabled.":
        "Enable log file validation to detect if CloudTrail log files have been modified or deleted after delivery.",
    "CloudTrail is not configured as a multi-region trail.":
        "Configure the trail as multi-region to ensure comprehensive coverage of all AWS regions.",
    "Default route to an Internet Gateway detected; verify if intended for public subnets.":
        "Ensure that default routes to an Internet Gateway are only associated with public subnets. For private subnets requiring outbound internet access, use a NAT Gateway or NAT Instance.",
    "Overly permissive rule allowing all traffic from 0.0.0.0/0 detected.":
        "Tighten Network ACL rules to restrict inbound and outbound traffic to only necessary protocols, ports, and specific source/destination IP ranges, following the principle of least privilege.",
    "Subnet is configured to automatically assign public IPs, which may indicate unintended public exposure.":
        "Review subnets with 'auto-assign public IP' enabled. Disable this feature for private subnets to prevent unintended direct exposure to the internet. Ensure resources in these subnets that require public IPs are intentionally configured as such.",
    "VPC Flow Logs are not enabled, which may hinder network traffic monitoring.":
        "Enable VPC Flow Logs for the VPC to capture IP traffic information. This is crucial for network monitoring, security analysis, and troubleshooting."
}

# --- Text wrapping function for DataFrame cells ---
def wrap_text_for_df(text, width=50):
    if not isinstance(text, str):
        text = str(text)
    return textwrap.fill(text, width=width, break_long_words=True, replace_whitespace=False)

def get_recommendation(issue_text):
    """Get recommendation for a specific issue"""
    # Check for exact matches first
    if issue_text in recommended_actions:
        return recommended_actions[issue_text]
    
    # Check for partial matches
    for key in recommended_actions:
        if key in issue_text:
            return recommended_actions[key]
    
    return "Review this issue and apply security best practices."

def load_scan_history():
    """Load all historical scans"""
    history_dir = os.path.join(os.path.dirname(__file__), "scan_history")
    if not os.path.exists(history_dir):
        return []
    
    history_files = glob.glob(os.path.join(history_dir, "scan_*.json"))
    history = []
    
    for file_path in sorted(history_files, reverse=True):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                history.append({
                    "file": file_path,
                    "timestamp": data.get("scan_timestamp", "Unknown"),
                    "data": data
                })
        except Exception as e:
            st.warning(f"Error loading {file_path}: {e}")
    
    return history


# --- Executes the compliance checks from checker.py ---
def run_compliance_checks():
    try:
        import subprocess
        import sys
        
        # Run checker.py and capture output
        result = subprocess.run(
            [sys.executable, "checker.py"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(__file__) or "."
        )
        
        if result.returncode != 0:
            st.error(f"Error running compliance checks: {result.stderr}")
            return None
        
        # Parse JSON output
        try:
            results = json.loads(result.stdout)
            return results
        except json.JSONDecodeError as e:
            st.error(f"Error parsing scan results: {e}")
            st.text("Output received:")
            st.code(result.stdout[:1000])
            return None
            
    except ImportError:
        st.warning("checker.py not found. Using dummy data for demonstration.")
        # Fallback to dummy data if the main checker script is missing
        dummy_results = {
            "scan_timestamp": datetime.now().isoformat(),
            "regions_scanned": ["eu-north-1"],
            "summary": {
                "total_issues": 5,
                "by_severity": {"Critical": 2, "High": 1, "Medium": 1, "Low": 1},
                "by_category": {"S3_Compliance_Issues": 2, "EC2_SG_Issues": 2, "IAM_Issues": 1}
            },
            "results": {
                "eu-north-1": {
                    "S3_Compliance_Issues": [
                        {"Bucket": "my-sample-bucket-1", "Issues": [
                            {"Issue": "Public access is allowed due to misconfigured Public Access Block settings.", 
                             "DORA_Mapping": "DORA_S3_1.1", "Severity": "Critical"},
                            {"Issue": "Bucket encryption is not enabled.", 
                             "DORA_Mapping": "DORA_S3_2.1", "Severity": "High"}
                        ]}
                    ],
                    "EC2_SG_Issues": [
                        {"SecurityGroup": "sg-12345abc", "Issues": [
                            {"Issue": "SSH (port 22) publicly accessible", 
                             "DORA_Mapping": "DORA_EC2_1.1", "Severity": "Critical"},
                            {"Issue": "ICMP (Ping) publicly accessible", 
                             "DORA_Mapping": "DORA_EC2_1.2", "Severity": "Low"}
                        ]}
                    ],
                    "IAM_Issues": [
                        {"User": "test-user", "Issues": [
                            {"Issue": "User does not have MFA enabled.", 
                             "DORA_Mapping": "DORA_IAM_MFA_1.0", "Severity": "High"}
                        ]}
                    ],
                    "VPC_Issues": [],
                    "RDS_Issues": [],
                    "CloudTrail_Issues": []
                }
            }
        }
        return dummy_results

def export_to_csv(scan_data):
    """Export scan results to CSV format"""
    rows = []
    results = scan_data.get("results", {})
    
    for region, categories in results.items():
        for category, items in categories.items():
            for item in items:
                resource = (
                    item.get("Bucket") or item.get("SecurityGroup") or 
                    item.get("Role") or item.get("User") or 
                    item.get("RouteTable") or item.get("NetworkACL") or 
                    item.get("Subnet") or item.get("VPC") or 
                    item.get("DBInstance") or item.get("Trail") or 
                    "Unknown Resource"
                )
                for issue_obj in item.get("Issues", []):
                    rows.append({
                        "Region": region,
                        "Category": category,
                        "Resource": resource,
                        "Issue": issue_obj.get("Issue", "Unknown"),
                        "Severity": issue_obj.get("Severity", "Low"),
                        "DORA Mapping": issue_obj.get("DORA_Mapping", "N/A"),
                        "Recommendation": get_recommendation(issue_obj.get("Issue", ""))
                    })
    
    df = pd.DataFrame(rows)
    return df.to_csv(index=False)

# --- Generates the PDF report from scan results ---
def generate_pdf_report(scan_data):
    pdf = FPDF(orientation='L') # Landscape mode for wider tables
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "AWS Compliance Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(3)
    
    # Add summary
    summary = scan_data.get("summary", {})
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Total Issues: {summary.get('total_issues', 0)}", ln=True)
    
    by_severity = summary.get("by_severity", {})
    pdf.cell(0, 6, f"Critical: {by_severity.get('Critical', 0)} | High: {by_severity.get('High', 0)} | " +
             f"Medium: {by_severity.get('Medium', 0)} | Low: {by_severity.get('Low', 0)}", ln=True)
    pdf.ln(5)

    # A4 landscape is 297mm wide. With 10mm margins, effective width is 277mm.
    effective_page_width = 297 - 20
    
    headers = ["Resource", "Issue", "Severity", "DORA Mapping", "Recommendation"]
    col_widths_percent = [0.12, 0.25, 0.08, 0.15, 0.40] 
    col_widths = [effective_page_width * w for w in col_widths_percent]
    line_height = 5 # mm
    header_height = 7 # mm

    results = scan_data.get("results", {})
    
    for region, categories in results.items():
        pdf.set_font("Arial", "B", 14)
        if pdf.get_y() + 10 > pdf.page_break_trigger:
            pdf.add_page()
        pdf.cell(0, 10, f"Region: {region}", ln=True)
        
        for category, items in categories.items():
            pdf.set_font("Arial", "B", 12)
            
            # Add a new page if the category title and table header won't fit
            if pdf.get_y() + 10 + header_height + 5 > pdf.page_break_trigger:
                pdf.add_page()
            pdf.cell(0, 8, category.replace("_", " "), ln=True)

            if items:
                # Draw table header
                pdf.set_font("Arial", "B", 8)
                pdf.set_fill_color(200, 220, 255) # Light blue fill
                current_x = pdf.l_margin
                for i, header_text in enumerate(headers):
                    pdf.set_xy(current_x, pdf.get_y())
                    pdf.multi_cell(col_widths[i], header_height, header_text, border=1, align='C', fill=True)
                    current_x += col_widths[i]
                pdf.ln(header_height)

                pdf.set_font("Arial", "", 7)

                for item_data in items:
                    resource_name = (
                        item_data.get("Bucket") or item_data.get("SecurityGroup") or
                        item_data.get("Role") or item_data.get("User") or
                        item_data.get("RouteTable") or item_data.get("NetworkACL") or
                        item_data.get("Subnet") or item_data.get("VPC") or
                        item_data.get("DBInstance") or item_data.get("Trail") or
                        "Unknown Resource"
                    )

                    for issue_obj in item_data.get("Issues", []):
                        issue_text = issue_obj.get("Issue", "Unknown Issue")
                        severity = issue_obj.get("Severity", "Low")
                        mapping = issue_obj.get("DORA_Mapping", "N/A")
                        recommendation_text = get_recommendation(issue_text)
                        
                        row_contents = [resource_name, issue_text, severity, mapping, recommendation_text]

                        # Calculate max number of lines needed for the current row
                        max_lines_in_row = 0
                        for i, cell_text in enumerate(row_contents):
                            lines = pdf.multi_cell(col_widths[i], line_height, str(cell_text), border=0, align='L', split_only=True)
                            if len(lines) > max_lines_in_row:
                                max_lines_in_row = len(lines)
                        
                        actual_row_height = (max_lines_in_row if max_lines_in_row > 0 else 1) * line_height

                        # Check for page break before drawing the row
                        if pdf.get_y() + actual_row_height > pdf.page_break_trigger:
                            pdf.add_page()
                            # Redraw category title and table header on new page
                            pdf.set_font("Arial", "B", 12)
                            pdf.cell(0, 8, category.replace("_", " "), ln=True)
                            pdf.set_font("Arial", "B", 8)
                            pdf.set_fill_color(200, 220, 255)
                            current_x_newpage = pdf.l_margin
                            for i, header_text_newpage in enumerate(headers):
                                pdf.set_xy(current_x_newpage, pdf.get_y())
                                pdf.multi_cell(col_widths[i], header_height, header_text_newpage, border=1, align='C', fill=True)
                                current_x_newpage += col_widths[i]
                            pdf.ln(header_height)
                            pdf.set_font("Arial", "", 7)

                        # Draw the actual row cells
                        y_before_row = pdf.get_y()
                        current_x = pdf.l_margin
                        max_y_after_cell_in_row = y_before_row

                        for i, cell_text in enumerate(row_contents):
                            # Align all cells to the same starting Y for this row
                            pdf.set_xy(current_x, y_before_row)
                            
                            # Color code severity
                            if i == 2:  # Severity column
                                if cell_text == "Critical":
                                    pdf.set_fill_color(255, 200, 200)
                                elif cell_text == "High":
                                    pdf.set_fill_color(255, 220, 180)
                                elif cell_text == "Medium":
                                    pdf.set_fill_color(255, 255, 200)
                                else:
                                    pdf.set_fill_color(220, 255, 220)
                                pdf.multi_cell(col_widths[i], line_height, str(cell_text), border=1, align='L', fill=True)
                            else:
                                pdf.multi_cell(col_widths[i], line_height, str(cell_text), border=1, align='L')
                            
                            # Check if this cell made the row taller
                            if pdf.get_y() > max_y_after_cell_in_row:
                                max_y_after_cell_in_row = pdf.get_y()
                            current_x += col_widths[i]
                        
                        # Set the Y position to the bottom of the tallest cell in the row just drawn
                        pdf.set_y(max_y_after_cell_in_row)

                pdf.ln(5) # Add a small space after each table
            else:
                pdf.set_font("Arial", "I", 9)
                if pdf.get_y() + 10 > pdf.page_break_trigger:
                    pdf.add_page()
                    pdf.set_font("Arial", "B", 12)
                    pdf.cell(0, 8, category.replace("_", " "), ln=True)
                    pdf.set_font("Arial", "I", 9)
                pdf.cell(0, 6, "No issues detected for this category.", ln=True)
                pdf.ln(3)

    pdf_output = pdf.output(dest="S").encode("latin1")
    return pdf_output

# --- Custom CSS for enhanced table styling ---
enhanced_custom_css = """
<style>
    .table-container {
        display: flex;
        justify-content: center;
        width: 100%;
        margin-bottom: 25px;
        margin-top: 10px;
    }

    .custom-html-table {
        width: 95% !important;
        table-layout: fixed;
        border-collapse: collapse;
        margin-left: auto;
        margin-right: auto;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        border-radius: 8px;
        overflow: hidden;
        font-size: 0.85rem;
    }

    .custom-html-table th {
        background-color: #2c3e50;
        color: white;
        font-weight: 600;
        text-align: left;
        padding: 12px 10px;
        border: 1px solid #34495e;
        white-space: pre-wrap !important;
        word-wrap: break-word;
        overflow-wrap: break-word;
        vertical-align: top;
    }

    .custom-html-table td {
        text-align: left;
        padding: 10px 10px;
        border: 1px solid #ddd;
        white-space: pre-wrap !important;
        word-wrap: break-word;
        overflow-wrap: break-word;
        vertical-align: top;
        color: #333;
    }

    .custom-html-table tbody tr:nth-child(even) {
        background-color: #f8f9fa;
    }
    .custom-html-table tbody tr:nth-child(odd) {
        background-color: #ffffff;
    }

    .custom-html-table tbody tr:hover {
        background-color: #e9ecef;
    }

    /* Column width proportions for 5-column layout */
    .custom-html-table th:nth-child(1), .custom-html-table td:nth-child(1) { width: 12% !important; }
    .custom-html-table th:nth-child(2), .custom-html-table td:nth-child(2) { width: 25% !important; }
    .custom-html-table th:nth-child(3), .custom-html-table td:nth-child(3) { width: 8% !important; }
    .custom-html-table th:nth-child(4), .custom-html-table td:nth-child(4) { width: 18% !important; }
    .custom-html-table th:nth-child(5), .custom-html-table td:nth-child(5) { width: 37% !important; }

    /* Severity badges */
    .severity-critical { 
        background-color: #dc3545; 
        color: white; 
        padding: 3px 8px; 
        border-radius: 4px; 
        font-weight: bold;
        display: inline-block;
    }
    .severity-high { 
        background-color: #fd7e14; 
        color: white; 
        padding: 3px 8px; 
        border-radius: 4px; 
        font-weight: bold;
        display: inline-block;
    }
    .severity-medium { 
        background-color: #ffc107; 
        color: #000; 
        padding: 3px 8px; 
        border-radius: 4px; 
        font-weight: bold;
        display: inline-block;
    }
    .severity-low { 
        background-color: #28a745; 
        color: white; 
        padding: 3px 8px; 
        border-radius: 4px; 
        font-weight: bold;
        display: inline-block;
    }

    .stDownloadButton > button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 8px 12px;
        font-weight: bold;
        border: none;
        margin-top: 5px;
        margin-bottom: 10px;
    }
    .stDownloadButton > button:hover {
        background-color: #45a049;
    }

    /* DARK MODE SPECIFIC STYLES */
    @media (prefers-color-scheme: dark) {
        .custom-html-table {
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }

        .custom-html-table td {
            border: 1px solid #444;
            color: #e0e0e0;
        }

        .custom-html-table tbody tr:nth-child(even) {
            background-color: #2a2a2e;
        }
        .custom-html-table tbody tr:nth-child(odd) {
            background-color: #333333;
        }

        .custom-html-table tbody tr:hover {
            background-color: #4a4a4e;
        }
        
        .custom-html-table th {
            border: 1px solid #555;
        }
    }
</style>
"""

# --- Main Streamlit Dashboard Logic ---
def main():
    st.set_page_config(layout="wide", page_title="AWS Security Scanner")
    st.title("🔒 AWS Cloud Security Compliance Checker")
    st.markdown("""
    This dashboard displays real-time compliance checks on AWS resources,
    mapping detected misconfigurations to DORA compliance requirements with actionable recommendations.
    """)

    st.markdown(enhanced_custom_css, unsafe_allow_html=True)

    # ===== SIDEBAR =====
    st.sidebar.header("⚙️ Scan Controls")
    
    # Scan button
    if st.sidebar.button("🔍 Run New Scan", type="primary"):
        with st.spinner("Scanning AWS resources across all regions..."):
            scan_results = run_compliance_checks()
            if scan_results:
                st.session_state.results = scan_results
                st.session_state.last_run = datetime.now()
                st.success("✅ Scan completed successfully!")
                st.rerun()
            else:
                st.error("Scan failed. Check logs for details.")
    
    # Initialize session state if needed
    if "results" not in st.session_state:
        with st.spinner("Running initial scan..."):
            scan_results = run_compliance_checks()
            if scan_results:
                st.session_state.results = scan_results
                st.session_state.last_run = datetime.now()
    
    if "results" not in st.session_state or not st.session_state.results:
        st.error("No scan data available. Please check your AWS credentials and configuration.")
        return
    
    scan_data = st.session_state.results
    scan_timestamp = scan_data.get("scan_timestamp", datetime.now().isoformat())
    summary = scan_data.get("summary", {})
    results = scan_data.get("results", {})
    
    # Display scan timestamp
    st.sidebar.markdown(f"**Last Scan:** {datetime.fromisoformat(scan_timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
    st.sidebar.markdown("---")
    
    # ===== FILTERS =====
    st.sidebar.header("🔍 Filters")
    
    # Severity filter
    severity_options = ["All", "Critical", "High", "Medium", "Low"]
    selected_severity = st.sidebar.multiselect(
        "Severity Level",
        severity_options[1:],  # Exclude "All"
        default=["Critical", "High", "Medium", "Low"]
    )
    
    # Region filter
    available_regions = list(results.keys())
    selected_regions = st.sidebar.multiselect(
        "Regions",
        available_regions,
        default=available_regions
    )
    
    # Category filter
    all_categories = set()
    for region_data in results.values():
        all_categories.update(region_data.keys())
    all_categories = sorted(list(all_categories))
    
    selected_categories = st.sidebar.multiselect(
        "Categories",
        all_categories,
        default=all_categories
    )
    
    st.sidebar.markdown("---")
    
    # ===== EXPORT OPTIONS =====
    st.sidebar.header("📥 Export Options")
    
    # JSON export
    json_data = json.dumps(scan_data, indent=2)
    st.sidebar.download_button(
        label="📄 Download JSON",
        data=json_data,
        file_name=f"aws_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )
    
    # CSV export
    csv_data = export_to_csv(scan_data)
    st.sidebar.download_button(
        label="📊 Download CSV",
        data=csv_data,
        file_name=f"aws_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )
    
    # PDF export
    if st.sidebar.button("📑 Generate PDF Report"):
        with st.spinner("Generating PDF report..."):
            pdf_data = generate_pdf_report(scan_data)
            st.sidebar.download_button(
                label="💾 Download PDF",
                data=pdf_data,
                file_name=f"AWS_Compliance_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
    
    st.sidebar.markdown("---")
    
    # ===== HISTORICAL SCANS =====
    st.sidebar.header("📚 Scan History")
    history = load_scan_history()
    if history:
        st.sidebar.write(f"Found {len(history)} previous scans")
        selected_history = st.sidebar.selectbox(
            "View Historical Scan",
            options=["Current"] + [h["timestamp"] for h in history],
            index=0
        )
        
        if selected_history != "Current":
            for h in history:
                if h["timestamp"] == selected_history:
                    scan_data = h["data"]
                    summary = scan_data.get("summary", {})
                    results = scan_data.get("results", {})
                    st.info(f"Viewing historical scan from {selected_history}")
                    break
    else:
        st.sidebar.write("No previous scans found")
    
    # ===== SUMMARY DASHBOARD =====
    st.header("📊 Summary Dashboard")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Issues", summary.get("total_issues", 0))
    
    by_severity = summary.get("by_severity", {})
    with col2:
        st.metric("🔴 Critical", by_severity.get("Critical", 0))
    
    with col3:
        st.metric("🟠 High", by_severity.get("High", 0))
    
    with col4:
        st.metric("🟡 Medium", by_severity.get("Medium", 0))
    
    with col5:
        st.metric("🟢 Low", by_severity.get("Low", 0))
    
    st.markdown("---")
    
    # ===== DETAILED FINDINGS =====
    st.header("🔎 Detailed Findings")
    
    WRAP_WIDTH = 100
    
    for region in selected_regions:
        if region not in results:
            continue
            
        region_data = results[region]
        st.subheader(f"📍 Region: {region}")
        
        for category in selected_categories:
            if category not in region_data:
                continue
                
            items = region_data[category]
            
            st.markdown(f"### {category.replace('_', ' ')}")
            
            table_data = []
            if items:
                for item in items:
                    resource = (
                        item.get("Bucket") or item.get("SecurityGroup") or
                        item.get("Role") or item.get("User") or
                        item.get("RouteTable") or item.get("NetworkACL") or
                        item.get("Subnet") or item.get("VPC") or
                        item.get("DBInstance") or item.get("Trail") or
                        "Unknown Resource"
                    )
                    
                    for issue_obj in item.get("Issues", []):
                        severity = issue_obj.get("Severity", "Low")
                        
                        # Apply severity filter
                        if severity not in selected_severity:
                            continue
                        
                        issue_text = issue_obj.get("Issue", "Unknown Issue")
                        dora_mapping_text = issue_obj.get("DORA_Mapping", "N/A")
                        recommendation = get_recommendation(issue_text)
                        
                        # Format severity with color badge
                        severity_badge = f'<span class="severity-{severity.lower()}">{severity}</span>'
                        
                        table_data.append({
                            "Resource": wrap_text_for_df(resource, width=int(WRAP_WIDTH * 0.6)),
                            "Issue": wrap_text_for_df(issue_text, width=WRAP_WIDTH),
                            "Severity": severity_badge,
                            "DORA Mapping": wrap_text_for_df(dora_mapping_text, width=int(WRAP_WIDTH*0.7)),
                            "Recommendation": wrap_text_for_df(recommendation, width=WRAP_WIDTH + 15)
                        })

            if table_data:
                df = pd.DataFrame(table_data)
                
                # Replace newlines with HTML breaks for display
                df_display = df.copy()
                for col in df_display.columns:
                    if col != "Severity":  # Severity already has HTML
                        df_display[col] = df_display[col].apply(
                            lambda x: x.replace('\n', '<br>') if isinstance(x, str) else x
                        )
                
                html_table = df_display.to_html(escape=False, index=False, classes="custom-html-table")
                centered_html_table = f"<div class='table-container'>{html_table}</div>"
                st.markdown(centered_html_table, unsafe_allow_html=True)
            else:
                st.info("No issues detected for this category (or filtered out).")
        
        st.markdown("---")

if __name__ == '__main__':
    main()