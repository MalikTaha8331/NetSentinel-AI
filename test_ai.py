from app import create_app
from app.scanner.engine import run_scan
from app.scanner.cve import correlate_scan_with_cves
from app.ai.analyzer import analyze_scan_with_ai, chat_with_ai

app = create_app()

with app.app_context():
    print("🔍 Scanning...")
    result = run_scan('scanme.nmap.org', profile='quick')
    
    print("🔗 Correlating CVEs...")
    enriched = correlate_scan_with_cves(result)

    print("🤖 Analyzing with AI...")
    ai_analysis = analyze_scan_with_ai(enriched)

    print(f"\n{'='*55}")
    print(f"🤖 NETSENTINEL AI THREAT ASSESSMENT")
    print(f"{'='*55}")
    print(f"\n📋 Summary:\n{ai_analysis['threat_summary']}")
    print(f"\n🚨 Critical Findings:")
    for f in ai_analysis['critical_findings']:
        print(f"  • {f}")
    print(f"\n⚔️  Attack Vectors:")
    for a in ai_analysis['attack_vectors']:
        print(f"  • {a}")
    print(f"\n🛡️  Recommendations:")
    for r in ai_analysis['recommendations']:
        print(f"  • {r}")
    print(f"\n📊 Risk Explanation:\n{ai_analysis['risk_explanation']}")
    print(f"\n{'='*55}")
    print(f"💬 Testing AI Chat Assistant...")
    reply = chat_with_ai(enriched, "Which vulnerability should I patch first and why?")
    print(f"\nQ: Which vulnerability should I patch first and why?")
    print(f"AI: {reply}")