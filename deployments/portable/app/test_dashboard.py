from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/')
def test():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Dashboard</title>
        <style>
            body { font-family: Arial; background: #1e3c72; color: white; padding: 20px; }
            .header { text-align: center; margin-bottom: 20px; }
            .card { background: rgba(255,255,255,0.1); padding: 20px; margin: 10px; border-radius: 10px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ IDS/IPS Security Dashboard - TEST</h1>
            <p>Real-time Network Security Monitoring</p>
        </div>
        
        <div class="card">
            <h2>✅ Dashboard Working!</h2>
            <p>If you can see this page, Flask is working correctly.</p>
            <p>Current status: System operational</p>
        </div>
        
        <div class="card">
            <h2>🔍 Basic Stats</h2>
            <p>Threats Detected: 0</p>
            <p>Network Activity: Active</p>
            <p>System Status: Running</p>
        </div>
        
        <script>
            setTimeout(() => {
                document.body.style.background = 'linear-gradient(135deg, #1e3c72 0%, #2a5298 100%)';
            }, 1000);
        </script>
    </body>
    </html>
    '''

@app.route('/api/test')
def api_test():
    return {'status': 'working', 'message': 'API is responding correctly'}

if __name__ == '__main__':
    print("🔧 Starting simple test dashboard...")
    print("🌐 Open http://localhost:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=True)
