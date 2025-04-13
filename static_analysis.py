import streamlit as st
import json
import tempfile
import os
import subprocess
from streamlit_ace import st_ace
from groq import Groq

# DeepSeek API Configuration
API_KEY = "enter-your-groq-api-key"
client = Groq(api_key=API_KEY)

# Supported languages
LANGUAGE_TOOLS = {
    "python": {"tool": "bandit", "args": ["-f", "json", "-o"], "ext": ".py"},
    "cpp": {"ext": ".cpp"},
    "java": {"ext": ".java"},
    "javascript": {"ext": ".js"},
    "ruby": {"ext": ".rb"}
}

# Function to run security tools
def run_tool(tool, args):
    try:
        result = subprocess.run([tool] + args, capture_output=True, text=True)
        return result.stdout, result.stderr
    except FileNotFoundError:
        return None, None

# Function to extract Bandit issues
def extract_bandit_issues(bandit_output, code_lines):
    issues = []
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    if "results" in bandit_output:
        for result in bandit_output["results"]:
            line_number = result.get("line_number", "Unknown")
            severity = result.get("issue_severity", "UNKNOWN").upper()
            issue_text = result.get("issue_text", "No description available.")
            documentation_link = result.get("more_info", "https://bandit.readthedocs.io/")

            if severity in severity_counts:
                severity_counts[severity] += 1

            code_snippet = code_lines[line_number - 1].strip() if isinstance(line_number, int) else "Unknown Code"

            formatted_issue = (
                f"🔴 **[Line {line_number}] {issue_text}**\n"
                f"```python\n{code_snippet}\n```\n"
                f"- **Severity**: {severity}\n"
                f"- **Fix**: [Refer to documentation]({documentation_link})\n\n"
            )

            issues.append((line_number, formatted_issue))

    sorted_issues = [issue[1] for issue in sorted(issues, key=lambda x: x[0] if isinstance(x[0], int) else float('inf'))]
    return sorted_issues, severity_counts

# Function to extract Pylint score
def extract_pylint_score(pylint_output):
    scores = [item["message"] for item in pylint_output if item.get("type") == "score"]
    return float(scores[0]) if scores else 5.0

# Function to calculate final security score
def calculate_final_score(pylint_score, severity_counts):
    penalty = severity_counts["LOW"] * 1 + severity_counts["MEDIUM"] * 2 + severity_counts["HIGH"] * 3
    bandit_score = max(10 - penalty, 0)
    return (bandit_score * 0.5) + (pylint_score * 0.5)

# Function to run static analysis
def analyze_python_security(code):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file.write(code.encode("utf-8"))
        temp_path = temp_file.name

    _, _ = run_tool("bandit", ["-f", "json", "-o", "bandit_output.json", temp_path])
    pylint_stdout, _ = run_tool("pylint", ["--output-format=json", temp_path])

    bandit_output = {}
    if os.path.exists("bandit_output.json"):
        with open("bandit_output.json", "r") as f:
            try:
                bandit_output = json.load(f)
            except json.JSONDecodeError:
                pass
        os.remove("bandit_output.json")

    pylint_output = []
    if pylint_stdout:
        try:
            pylint_output = json.loads(pylint_stdout)
        except json.JSONDecodeError:
            pass

    os.remove(temp_path)

    code_lines = code.split("\n")
    bandit_issues, severity_counts = extract_bandit_issues(bandit_output, code_lines)
    pylint_score = extract_pylint_score(pylint_output)
    final_score = calculate_final_score(pylint_score, severity_counts)

    report = "\n📋 **Vulnerability Report**\n\n"
    if bandit_issues:
        report += "📌 **Critical Security Issues Found:**\n\n" + "\n\n".join(bandit_issues)
    else:
        report += "✅ No critical security issues found."
    report += f"\n\n📊 **Final Security Score:** {final_score:.2f}/10"

    return report, "\n".join(bandit_issues)


def get_fixed_code_with_deepseek(code, vulnerabilities, language):
    """Get fixed code from DeepSeek AI."""
    prompt = f"""
    The following {language} code may have security vulnerabilities.

    Code:
    {code}

    If vulnerabilities were found, please provide a secure, corrected version of the code first. 
    After that, give a brief explanation of the fixes.
    """
    
    messages = [
        {"role": "system", "content": "You are an AI-powered security code analyzer. Provide secure fixes based on the given static analysis report."},
        {"role": "user", "content": prompt}
    ]
    
    completion = client.chat.completions.create(
        model="deepseek-r1-distill-llama-70b",
        messages=messages,
        temperature=0.6,
        top_p=0.95,
        stream=True
    )
    
    fixed_code, explanation = "", ""
    collecting_fixed_code = True
    for chunk in completion:
        if hasattr(chunk, "choices") and chunk.choices:
            content = chunk.choices[0].delta.content
            if content:
                if collecting_fixed_code:
                    fixed_code += content
                else:
                    explanation += content
                if "Explanation:" in content:
                    collecting_fixed_code = False
    
    return fixed_code.strip(), explanation.strip()

def run_security_analysis(code, language):
    """Run static analysis if Python, else skip."""
    if language == "python":
        return analyze_python_security(code)
    else:
        return f"📋 Below is the fixed code and explaination to the vulnerabilites your code has: {language}.", ""

# ---- STREAMLIT UI ----
st.set_page_config(page_title="SentinelAI", page_icon="🛡", layout="wide")

st.title("🛡 SentinelAI – The AI Powered Code Guardian ")
st.markdown("### AI-Powered Security Vulnerability Detection & Auto-Fixing")

language = st.selectbox("Select programming language", list(LANGUAGE_TOOLS.keys()))
uploaded_file = st.file_uploader("📁 Upload a file", type=[LANGUAGE_TOOLS[language]["ext"].lstrip(".")])
code = st_ace(language=language, theme="dracula", font_size=14, height=250, key="code_editor")

if uploaded_file:
    code = uploaded_file.read().decode("utf-8")
    st.sidebar.success(f"📄 {uploaded_file.name} loaded successfully!")

if st.button("🔍 Run Security Scan") and code:
    with st.spinner("Analyzing code for vulnerabilities..."):
        report, vulnerabilities = run_security_analysis(code, language)
        st.markdown(report)
    
    with st.spinner("Generating secure fixed code..."):
        fixed_code, explanation = get_fixed_code_with_deepseek(code, vulnerabilities, language)
        st.subheader("🔧 AI-Generated Fixed Code")
        st.code(fixed_code, language=language)
        st.markdown(explanation)
    
    full_report = f"{report}\n\nFixed Code:\n\n{fixed_code}\n\nExplanation:\n\n{explanation}"
    st.download_button(
        label="📥 Download Complete Report",
        data=full_report,
        file_name="security_report.txt",
        mime="text/plain"
    )
