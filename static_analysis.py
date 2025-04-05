import streamlit as st
import json
import tempfile
import os
import subprocess
from streamlit_ace import st_ace

def run_tool(tool, args):
    """Runs a security tool and returns stdout and stderr output."""
    try:
        result = subprocess.run([tool] + args, capture_output=True, text=True)
        return result.stdout, result.stderr
    except FileNotFoundError:
        return None, None

def extract_bandit_issues(bandit_output, code_lines):
    """Extracts security vulnerabilities from Bandit output JSON."""
    issues = []
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    if "results" in bandit_output:
        for result in bandit_output["results"]:
            line_number = result.get("line_number", "Unknown")
            severity = result.get("issue_severity", "UNKNOWN").upper()
            issue_text = result.get("issue_text", "No description available.")
            documentation_link = result.get("more_info", "https://bandit.readthedocs.io/")

            # Count severity levels for final security score calculation
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Extract the actual line of code
            if isinstance(line_number, int) and 1 <= line_number <= len(code_lines):
                code_snippet = code_lines[line_number - 1].strip()
            else:
                code_snippet = "Unknown Code"

            formatted_issue = (
                f"🔴 **[Line {line_number}] {issue_text}**\n"
                f"```python\n{code_snippet}\n```\n"
                f"- **Severity**: {severity}\n"
                f"- **Risk**: {issue_text}\n"
                f"- **Fix**: [Refer to documentation]({documentation_link}) to mitigate this issue.\n\n"
            )

            issues.append((line_number, formatted_issue))

    # Sort issues by line number
    sorted_issues = [issue[1] for issue in sorted(issues, key=lambda x: x[0] if isinstance(x[0], int) else float('inf'))]

    return sorted_issues, severity_counts

def extract_pylint_score(pylint_output):
    """Extracts Pylint score from JSON output."""
    scores = [item["message"] for item in pylint_output if item.get("type") == "score"]
    return float(scores[0]) if scores else 5.0  # Default to 5 if no score is found

def calculate_final_score(pylint_score, severity_counts):
    """Computes the final security score based on tool results."""
    penalty = severity_counts["LOW"] * 1 + severity_counts["MEDIUM"] * 2 + severity_counts["HIGH"] * 3
    bandit_score = max(10 - penalty, 0)  # Ensure score doesn't go negative
    return (bandit_score * 0.5) + (pylint_score * 0.5)  # Weighted average

def run_static_analysis(code):
    """Runs Bandit and Pylint and returns a security report."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file.write(code.encode("utf-8"))
        temp_path = temp_file.name

    # Run Bandit
    _, _ = run_tool("bandit", ["-f", "json", "-o", "bandit_output.json", temp_path])

    # Run Pylint
    pylint_stdout, _ = run_tool("pylint", ["--output-format=json", temp_path])

    # Read Bandit output
    bandit_output = {}
    if os.path.exists("bandit_output.json"):
        with open("bandit_output.json", "r") as f:
            try:
                bandit_output = json.load(f)
            except json.JSONDecodeError:
                pass
        os.remove("bandit_output.json")

    # Read Pylint output
    pylint_output = []
    if pylint_stdout:
        try:
            pylint_output = json.loads(pylint_stdout)
        except json.JSONDecodeError:
            pass

    os.remove(temp_path)  # Cleanup temporary file

    # Parse detected issues
    code_lines = code.split("\n")
    bandit_issues, severity_counts = extract_bandit_issues(bandit_output, code_lines)
    pylint_score = extract_pylint_score(pylint_output)
    final_score = calculate_final_score(pylint_score, severity_counts)

    # Generate the final vulnerability report
    report = "\n📋 **Vulnerability Report**\n\n"

    if bandit_issues:
        report += "📌 **Critical Security Issues Found:**\n\n"
        report += "\n\n".join(bandit_issues)
    else:
        report += "✅ No critical security issues found."

    report += f"\n\n📊 **Final Security Score:** {final_score:.2f}/10"

    return report

# ---- STREAMLIT UI ----
st.set_page_config(page_title="SentinelAI", page_icon="🛡", layout="wide")

st.title("🛡 SentinelAI – AI Code Guardian")
st.markdown("### AI-Powered Code Vulnerability Detection")

uploaded_file = st.file_uploader("📁 Upload a Python file", type=["py"])
code = st_ace(language="python", theme="dracula", font_size=14, height=250, key="code_editor")

if uploaded_file:
    code = uploaded_file.read().decode("utf-8")
    st.sidebar.success(f"📄 {uploaded_file.name} loaded successfully!")

if st.button("🔍 Run Security Scan") and code:
    with st.spinner("Analyzing code for vulnerabilities..."):
        vulnerabilities = run_static_analysis(code)
        st.markdown(vulnerabilities)
