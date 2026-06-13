from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from app import db
from app.scanner.engine import run_scan
from app.scanner.cve import correlate_scan_with_cves
from app.scanner.ml_engine import run_ml_analysis
from app.scanner.models import ScanResult
from app.ai.analyzer import analyze_scan_with_ai, chat_with_ai

main = Blueprint('main', __name__)

@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    scans = ScanResult.query.order_by(ScanResult.scan_time.desc()).limit(20).all()
    return render_template('dashboard.html', scans=scans)

@main.route('/api/scan/full', methods=['POST'])
@login_required
def full_scan():
    data = request.get_json()
    host = data.get('host')
    profile = data.get('profile', 'quick')

    if not host:
        return jsonify({'error': 'Host is required'}), 400

    # Step 1: Scan
    result = run_scan(host, profile=profile)
    if 'error' in result:
        return jsonify(result), 400

    # Step 2: CVE Correlation
    result = correlate_scan_with_cves(result)

    # Step 3: ML Analysis
    result = run_ml_analysis(result)

    # Step 4: AI Analysis
    try:
        ai_analysis = analyze_scan_with_ai(result)
        result['ai_analysis'] = ai_analysis
    except Exception as e:
        result['ai_analysis'] = None

    # Step 5: Save to DB
    scan_record = ScanResult(
        hostname=result['hostname'],
        ip=result['ip'],
        profile=result['profile'],
        duration=result['duration'],
        total_ports_scanned=result['total_ports_scanned'],
        open_count=result['open_count'],
        risk_score=result.get('risk_score', 'Pending'),
        ai_summary=str(result.get('ai_analysis', ''))
    )
    scan_record.set_ports(result['open_ports'])
    db.session.add(scan_record)
    db.session.commit()

    result['scan_id'] = scan_record.id
    return jsonify(result)

@main.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    message = data.get('message')
    scan_id = data.get('scan_id')
    chat_history = data.get('chat_history', [])

    scan = ScanResult.query.get_or_404(scan_id)
    scan_data = scan.to_dict()

    reply = chat_with_ai(scan_data, message, chat_history)
    return jsonify({'reply': reply})

@main.route('/api/scans', methods=['GET'])
@login_required
def get_scans():
    scans = ScanResult.query.order_by(ScanResult.scan_time.desc()).all()
    return jsonify([s.to_dict() for s in scans])

@main.route('/api/scan/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())