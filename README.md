
# SentinelAI – The AI-Powered Code Guardian

## 📌 Table of Contents

| Section       | Description                                  |
|---------------|----------------------------------------------|
| Description| Overview of the project and its purpose     |
| Features      | Key functionalities offered by the project |
| Working         | Step-by-step explanation of how it works  |
| Tech Stack  | Technologies and tools used              |
| Installation | How to install and set up the project     |
| Demo              | Screenshots or video demo of the project |
| Contributors | Project authors and contributors         |

## 🔐 Description
Cybersecurity code is a hacker’s playground in today's rising cyber threats. Manual code reviews and security audits are slow, error-prone, and often miss critical vulnerabilities. Developers often unknowingly introduce serious security flaws, from SQL Injections and Hardcoded Secrets to broken authentication and XSS Attacks.

This AI-powered tool brings security to your fingertips — fast, accurate, and real-time.


## 🚀 Features

🔍 **Real-Time Vulnerability Detection**

  - Scans Python, Java, JavaScript, and C/C++ code for issues like SQL injection, XSS, command injection, and buffer overflows.

🧠 **Static Analysis - tools**

 -  Tools used to detect and create vulnerability report - Bandit, Pylint, ESLint, spotbugs, Cppcheck.

🧠 **AI-Powered Security Insights**
 
- Uses Groq's high-speed LLMs to analyze code contextually and suggest secure coding practices.

🛡️ **Secure Coding Recommendations**

- Each vulnerability includes severity levels (Low, Medium, High) and actionable remediation tips.

✍️ **Integrated Code Editor**

- Built-in Streamlit editor for instant analysis of pasted or written code — no setup or login required.

## 🛠️ Working

### 1. 📝 User Input
The user can input the source code in two ways:
- Typing or pasting code directly into the real-time code editor built using Streamlit.
- Uploading a file — the file must match the selected language extension in the select language dropdown bar:
  
  - `.py` for Python
    
  - `.java` for Java
    
  - `.js` for JavaScript
    
  - `.cpp`, `.c` for C/C++

### 2. 🌍 Language Detection
- SentinelAI detects the programming language of the input code using libraries like `pygments` or `guesslang`.
  
- This ensures the correct static analysis tool is applied based on the detected language.

### 3. 🧪 Static Analysis
- Once the language is identified, the appropriate static analysis tool is invoked:
  - Python → Bandit, Pylint  
  - JavaScript → ESLint
  - Java → spotbugs 
  - C/C++ → Cppcheck  

- These tools analyze the code for common security vulnerabilities and generate a line-by-line report including:
  - Type of vulnerability (e.g., SQL Injection, XSS)
  - Affected line of code
  - Severity level (e.g., High, Medium)
  - Suggested remediation
  - Security score
  - Generate a summary of the vulnerabilities in the code

### 4. 🌐 Multilingual Support
Supports secure code analysis across multiple languages:
- Python  
- JavaScript  
- Java  
- C/C++
  
### 5. 🤖 GenAI Integration (Groq API + DeepSeek Model)
- The report generated by the static analysis is passed to a large language model (LLM) via Groq API using DeepSeek.
- The model responds with:
  
  - A secure version of the affected code
    
  - A human-readable explanation of the vulnerability and the fix
    
- The AI-generated output is streamed in real-time through the user interface.

### 6. 📊 Smart Output
- Presents all detected vulnerabilities with:
  
  - Type, severity, affected line, and remediation
    
  - LLM-generated secure code fix and explanation
    
- Displays a message if no issues are found.
  
- All results are shown in a clear, user-friendly UI built with Streamlit.

## 🧰 Tech Stack

- 🐍 Python 3.10+  
- 🎨 Streamlit  
- 🤖 HuggingFace Transformers  
- ⚡ Groq API (DeepSeek Model)  
- 🛠️ Static Tools: Bandit, Pylint, ESLint etc.  
- 🌐 Pygments, Guesslang (Language Detection)


## Installation

To deploy this project run to install the required libraries:

```bash
  pip install transformers datasets accelerate torch peft bandit pylint semgrep

```
- In case it shows an error, try installing them one by one.

## Demo

![WhatsApp Image 2025-04-06 at 09 45 37_787285f4](https://github.com/user-attachments/assets/3329dd66-190f-4b34-ba3f-263de5806b76)


## 🙌 Contributors

- 👨‍💻 Priya Verma
- 👩‍💻 Jayavarshini. K.S
- 👨‍💻 Keerthana. R

## 🎉Fun Fact<Don't ever run this>

![WhatsApp Image 2025-04-05 at 20 41 06_70de873c](https://github.com/user-attachments/assets/15daafb4-db59-48d7-94c8-85b8c7823b56)
