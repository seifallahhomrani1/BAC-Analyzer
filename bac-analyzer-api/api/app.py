"""
REST API for BAC Analyzer - Broken Access Control Detection Tool
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import json
import tempfile
import shutil
from pathlib import Path

app = Flask(__name__)
CORS(app)  # Enable CORS for web interface

# Base directory for the analyzer
ANALYZER_DIR = Path("/workspace/bac-analyzer")

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    Start a BAC analysis scan
    Expects JSON with configuration parameters
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['tokens', 'endpoints']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create temporary directory for this scan
        temp_dir = Path(tempfile.mkdtemp(prefix="bac_scan_"))
        
        try:
            # Write configuration files to temp directory
            tokens_file = temp_dir / "tokens.json"
            with open(tokens_file, 'w') as f:
                json.dump(data['tokens'], f, indent=2)
            
            endpoints_file = temp_dir / "endpoints.yaml"
            with open(endpoints_file, 'w') as f:
                import yaml
                yaml.safe_dump({'endpoints': data['endpoints']}, f)
            
            # Use default matrix if not provided
            if 'matrix' in data:
                matrix_file = temp_dir / "authorization_matrix.yaml"
                with open(matrix_file, 'w') as f:
                    import yaml
                    yaml.safe_dump({'matrix': data['matrix']}, f)
            else:
                # Copy default matrix from analyzer directory
                default_matrix = ANALYZER_DIR / "authorization_matrix.yaml"
                if default_matrix.exists():
                    shutil.copy(default_matrix, temp_dir / "authorization_matrix.yaml")
            
            # Run the analyzer script
            cmd = ["python3", str(ANALYZER_DIR / "analyzer.py")]
            
            # Add optional parameters
            if data.get('run_diff', False):
                cmd.append("--diff")
            if 'proxy' in data:
                cmd.extend(["--proxy", data['proxy']])
            if 'base_url' in data:
                cmd.extend(["--base-url", data['base_url']])
            
            # Execute in temp directory
            result = subprocess.run(
                cmd,
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Read the generated report
            report_file = temp_dir / "report.json"
            if report_file.exists():
                with open(report_file, 'r') as f:
                    report = json.load(f)
            else:
                report = {}
            
            # Prepare response
            response = {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'report': report,
                'returncode': result.returncode
            }
            
            return jsonify(response)
        
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_default_config():
    """
    Get default configuration files
    """
    try:
        config = {}
        
        # Load default tokens
        tokens_file = ANALYZER_DIR / "tokens.json"
        if tokens_file.exists():
            with open(tokens_file, 'r') as f:
                config['tokens'] = json.load(f)
        
        # Load default endpoints
        endpoints_file = ANALYZER_DIR / "endpoints.yaml"
        if endpoints_file.exists():
            with open(endpoints_file, 'r') as f:
                import yaml
                config['endpoints'] = yaml.safe_load(f).get('endpoints', [])
        
        # Load default matrix
        matrix_file = ANALYZER_DIR / "authorization_matrix.yaml"
        if matrix_file.exists():
            with open(matrix_file, 'r') as f:
                import yaml
                config['matrix'] = yaml.safe_load(f).get('matrix', {})
        
        return jsonify(config)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """
    Test connection to an endpoint with a specific token
    """
    try:
        data = request.get_json()
        
        if 'url' not in data or 'token' not in data:
            return jsonify({'error': 'Missing url or token'}), 400
        
        import requests
        
        headers = {
            'Authorization': f'Bearer {data["token"]}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            data['url'],
            headers=headers,
            timeout=30
        )
        
        return jsonify({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'success': True
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)