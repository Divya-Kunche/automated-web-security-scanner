# automated-web-security-scanner
A Python-based automated web scanner that checks HTTP security headers, identifies missing headers, examines potential CORS misconfigurations, and generates a security audit report.
Automated Web Security Scanner Using Python

1. Project Description

The Automated Web Security Scanner Using Python is a simple security tool that checks websites for missing HTTP security headers and potential Cross-Origin Resource Sharing (CORS) misconfigurations.

It helps users understand basic website security configurations and provides recommendations for improving security.

2. Objectives

- To automate basic website security checks.
- To identify missing security headers.
- To inspect CORS response headers.
- To provide simple security recommendations.
- To improve awareness of web security.

3. Technologies Used

- Programming Language: Python
- Library: Requests
- Concepts: HTTP, Security Headers, CORS

4. Requirements

- Python 3.9 or later
- Internet connection
- Requests library
- Code editor such as VS Code or IDLE

5. Installation

Install the required Python library using:

python -m pip install requests

6. How to Run

1. Save the Python program as "web_security_scanner.py".
2. Open a terminal in the project folder.
3. Run the following command:

python web_security_scanner.py

4. Enter the URL of a website you own or have permission to test.
5. Review the security header results and recommendations.

7. Security Checks

The scanner checks for:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials

8. Expected Output

The program displays:

- Target website URL
- HTTP response status
- Present security headers
- Missing headers that need review
- Potentially permissive CORS settings
- Recommendations for further investigation

9. Limitations

- Checks only selected security headers and CORS settings.
- Does not perform a complete penetration test.
- Findings require manual review and do not prove that a website is vulnerable or secure.
- Results depend on the website's HTTP response.

10. Ethical Use

Use this tool only on websites you own or have explicit permission to assess. Do not use it to access private information or disrupt website services.

11. Author Details

Name: Kunche Divya
Department: CSE (AI & ML)
College: Ideal Institute of Technology

12. Conclusion

This project demonstrates how Python can automate basic web security configuration checks. It helps beginners understand HTTP security headers, CORS, and the importance of secure website configurations.
