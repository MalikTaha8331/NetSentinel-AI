from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
from app import db
from app.scanner.engine import run_scan
from app.scanner.models import ScanResult

main = Blueprint('main', __name__)

@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    scans = ScanResult.query.order_by(ScanResult.scan_time.desc()).limit(10).all()
    return render_template('dashboard.html', scans=scans)

@main.route('/api/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json()
    host = data.get('host')
    profile = data.get('profile', 'quick')

    if not host:
        return jsonify({'error': 'Host is required'}), 400

    result = run_scan(host, profile=profile)

    if 'error' in result:
        return jsonify(result), 400

    # Save to database
    scan_record = ScanResult(
        hostname=result['hostname'],
        ip=result['ip'],
        profile=result['profile'],
        duration=result['duration'],
        total_ports_scanned=result['total_ports_scanned'],
        open_count=result['open_count']
    )
    scan_record.set_ports(result['open_ports'])
    db.session.add(scan_record)
    db.session.commit()

    result['scan_id'] = scan_record.id
    return jsonify(result)

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