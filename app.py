import streamlit as st
import json
import tempfile
import os
import subprocess
from streamlit_ace import st_ace
from groq import Groq

# DeepSeek API Configuration
API_KEY = "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"
client = Groq(api_key=API_KEY)

# Supported languages
LANGUAGE_TOOLS = {
    "python": {"tool": "bandit", "args": ["-f", "json", "-o"], "ext": ".py"},
    "cpp": {"ext": ".cpp"},
    "java": {"ext": ".java"},
    "javascript": {"ext": ".js"},
    "ruby": {"ext": ".rb"}
}

def analyze_python_security(code):
    """Analyze Python code using Bandit."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file.write(code.encode("utf-8"))
        temp_path = temp_file.name
    
    try:
        result = subprocess.run(["bandit", "-f", "json", "-o", "bandit_output.json", temp_path], 
                              capture_output=True, text=True)
        
        if os.path.exists("bandit_output.json"):
            with open("bandit_output.json", "r") as f:
                report_data = json.load(f)
            os.remove("bandit_output.json")
            
            issues = []
            for result in report_data.get("results", []):
                issues.append(f"Line {result['line_number']}: {result['issue_text']} (Severity: {result['issue_severity']})")
            
            report = "\n📋 Python Vulnerability Report\n\n"
            if issues:
                report += "📌 Critical Security Issues Found:\n\n" + "\n".join(issues)
            else:
                report += "✅ No critical security issues found."
            
            return report, "\n".join(issues)
        return "Error: No report generated", ""
    finally:
        os.remove(temp_path)

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

st.title("🛡 SentinelAI – Multi-Language Security Analysis")
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
