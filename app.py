from flask import Flask, render_template
import re
from collections import Counter

app = Flask(__name__)

# Configuration
LOG_FILE = "sample.log"
FAILED_LOGIN_THRESHOLD = 3

def analyze_logs(file_path):
    failed_attempts = Counter()
    pattern = r"\[(\d{1,3}(?:\.\d{1,3}){3})\] FAILED LOGIN"
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    ip_address = match.group(1)
                    failed_attempts[ip_address] += 1
    except FileNotFoundError:
        return None
    
    # Process data and assign severity levels
    report = []
    for ip, count in failed_attempts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            severity = "High"
        elif count == 2:
            severity = "Medium"
        else:
            severity = "Low"
            
        report.append({"ip": ip, "count": count, "severity": severity})
    
    # Sort the report so High severity threats appear at the top
    report = sorted(report, key=lambda x: x['count'], reverse=True)
    return report

@app.route('/')
def dashboard():
    # Run the analysis and pass the data to the HTML template
    report_data = analyze_logs(LOG_FILE)
    return render_template('index.html', report=report_data)

if __name__ == '__main__':
    # Runs the web server on http://127.0.0.1:5000
    app.run(debug=True)