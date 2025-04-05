
# SentinelAI – The AI-Powered Code Guardian

## 🔐 Description
In today’s world of rising cyber threats, insecure code is a hacker’s playground. Manual code reviews and security audits are slow, error-prone, and often miss critical vulnerabilities. Developers, often unknowingly, introduce serious security flaws — from SQL Injections and Hardcoded Secrets to Broken Authentication and XSS Attacks.

This AI-powered tool brings security to your fingertips — fast, accurate, and real-time.


## 🚀 Features


🔍 Real-Time Vulnerability Detection
Scans Python, JavaScript, and C/C++ code for issues like SQL injection, XSS, command injection, and buffer overflows using regex-based rules.

🧠 AI-Powered Security Insights
Uses Groq's high-speed LLMs (e.g., DeepSeek) to analyze code contextually and suggest secure coding practices.

🛡️ Secure Coding Recommendations
Each vulnerability includes severity levels (Low, Medium, High) and actionable remediation tips.

✍️ Integrated Code Editor
Built-in Streamlit editor for instant analysis of pasted or written code — no setup or login required.

📡 Groq API Integration
Fast, cost-effective AI response generation with support for streaming and low-latency inference.

🔧 Extendable Rules Engine
Easily add or modify regex patterns for new vulnerabilities or additional language support.

📁 Dataset-Ready Architecture
Designed for future integration with labeled datasets or CodeBERT/LoRA fine-tuning workflows.
## Deployment

To deploy this project run to install the required libraries:

```bash
  pip install transformers 

```
```bash
  pip install datasets 

```

```bash
  pip install accelerate torch 

```

```bash
  pip install peft bandit pylint

```


