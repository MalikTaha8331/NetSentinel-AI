import json
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv('GROQ_API_KEY'))
MODEL = "llama-3.3-70b-versatile"

def analyze_scan_with_ai(scan_result):
    open_ports = scan_result.get('open_ports', [])
    risk_score = scan_result.get('risk_score', 'Unknown')
    host = scan_result.get('hostname', scan_result.get('host', 'Unknown'))
    ip = scan_result.get('ip', 'Unknown')

    ports_summary = []
    for p in open_ports:
        cve_list = [f"{c['id']} ({c['severity']}, CVSS:{c['score']})" for c in p.get('cves', [])]
        ports_summary.append(
            f"Port {p['port']} ({p['service']}) | Banner: {p.get('banner', 'None')} | CVEs: {', '.join(cve_list) if cve_list else 'None'}"
        )

    prompt = f"""You are NetSentinel AI, an expert cybersecurity analyst.

Analyze this network scan result and provide a professional threat assessment:

Target: {host} ({ip})
Overall Risk Score: {risk_score}
Open Ports:
{chr(10).join(ports_summary)}

Provide your response in this exact JSON format:
{{
    "threat_summary": "2-3 sentence overall assessment of the target security posture",
    "critical_findings": ["finding 1", "finding 2"],
    "attack_vectors": ["How an attacker could exploit finding 1", "How an attacker could exploit finding 2"],
    "recommendations": ["Fix 1", "Fix 2", "Fix 3"],
    "risk_explanation": "Why this host received a {risk_score} risk rating"
}}

Return ONLY valid JSON, no extra text."""

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )

    text = response.choices[0].message.content.strip()
    if text.startswith('```'):
        text = text.split('```')[1]
        if text.startswith('json'):
            text = text[4:]

    return json.loads(text.strip())


def chat_with_ai(scan_result, user_message, chat_history=None):
    open_ports = scan_result.get('open_ports', [])
    risk_score = scan_result.get('risk_score', 'Unknown')
    host = scan_result.get('hostname', 'Unknown')

    ports_summary = []
    for p in open_ports:
        cve_list = [f"{c['id']} ({c['severity']})" for c in p.get('cves', [])]
        ports_summary.append(
            f"Port {p['port']} ({p['service']}) - CVEs: {', '.join(cve_list) if cve_list else 'None'}"
        )

    system_prompt = f"""You are NetSentinel AI, an expert cybersecurity analyst assistant.

You are analyzing this scan result:
Target: {host} | Risk: {risk_score}
Open Ports:
{chr(10).join(ports_summary)}

Answer the user's questions about this scan professionally and clearly.
Be specific, actionable, and concise. Use plain English."""

    messages = [{"role": "system", "content": system_prompt}]
    if chat_history:
        messages.extend(chat_history)
    messages.append({"role": "user", "content": user_message})

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=500,
        messages=messages
    )

    return response.choices[0].message.content.strip()