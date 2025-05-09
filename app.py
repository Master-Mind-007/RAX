from flask import Flask, render_template, jsonify, request, send_from_directory
import logging
from datetime import datetime
import random
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Simulated device data
devices = {
    "device1": {
        "id": "device1",
        "name": "Device 1",
        "status": "active",
        "cpu_usage": 45,
        "ram_usage": {"used": 2.5, "total": 8},
        "uptime": "5h 23m",
        "ip_address": "192.168.1.100"
    },
    "device2": {
        "id": "device2",
        "name": "Device 2",
        "status": "inactive",
        "cpu_usage": 0,
        "ram_usage": {"used": 0, "total": 16},
        "uptime": "0h 0m",
        "ip_address": "192.168.1.101"
    },
    "device3": {
        "id": "device3",
        "name": "Device 2",
        "status": "inactive",
        "cpu_usage": 0,
        "ram_usage": {"used": 0, "total": 16},
        "uptime": "0h 0m",
        "ip_address": "192.168.1.101"
    },
    "device4": {
        "id": "device4",
        "name": "Device 2",
        "status": "inactive",
        "cpu_usage": 0,
        "ram_usage": {"used": 0, "total": 16},
        "uptime": "0h 0m",
        "ip_address": "192.168.1.101"
    }
}

def generate_keylog_data():
    """Generate simulated keylog data"""
    keys = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
            "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            "ENTER", "SPACE", "BACKSPACE"]
    logs = []
    for _ in range(10):
        timestamp = datetime.now().strftime("%H:%M:%S")
        key = random.choice(keys)
        logs.append(f"[{timestamp}] Key pressed: {key}")
    return "\n".join(logs)

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html', devices=devices.values())

@app.route('/api/devices/<device_id>/status')
def get_device_status(device_id):
    """Get the status of a specific device"""
    if device_id in devices:
        device = devices[device_id]
        if device["status"] == "active":
            # Simulate random changes for active devices
            device["cpu_usage"] = random.randint(20, 80)
            device["ram_usage"]["used"] = round(random.uniform(1.5, device["ram_usage"]["total"] - 1), 1)
        return jsonify(device)
    return jsonify({"error": "Device not found"}), 404

@app.route('/api/devices/<device_id>/keylog')
def get_device_keylog(device_id):
    """Get keylog data for a specific device"""
    if device_id in devices:
        if devices[device_id]["status"] == "active":
            return jsonify({
                "timestamp": datetime.now().isoformat(),
                "logs": generate_keylog_data()
            })
        return jsonify({"error": "Device is inactive"}), 400
    return jsonify({"error": "Device not found"}), 404

@app.route('/api/devices/<device_id>/screenshot')
def get_device_screenshot(device_id):
    """Get screenshot data for a specific device"""
    if device_id in devices:
        if devices[device_id]["status"] == "active":
            # Simulate screenshot with a placeholder SVG
            screenshot_url = f"data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTkyMCIgaGVpZ2h0PSIxMDgwIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9IiMzMzMiLz48dGV4dCB4PSI1MCUiIHk9IjUwJSIgZG9taW5hbnQtYmFzZWxpbmU9Im1pZGRsZSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iI2ZmZiIgZm9udC1zaXplPSIyNHB4Ij5TY3JlZW5zaG90IFNpbXVsYXRpb24gLSB7ZGV2aWNlX2lkfTwvdGV4dD48L3N2Zz4="
            return jsonify({
                "timestamp": datetime.now().isoformat(),
                "screenshot_url": screenshot_url
            })
        return jsonify({"error": "Device is inactive"}), 400
    return jsonify({"error": "Device not found"}), 404

@app.route('/api/devices/<device_id>/console', methods=['POST'])
def execute_console_command(device_id):
    """Execute a console command on a specific device"""
    if device_id in devices:
        if devices[device_id]["status"] == "active":
            command = request.json.get('command')
            if not command:
                return jsonify({"error": "No command provided"}), 400
            
            # Simulate command execution
            return jsonify({
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "output": f"Simulated output for command: {command}\nExecuted on {devices[device_id]['name']}"
            })
        return jsonify({"error": "Device is inactive"}), 400
    return jsonify({"error": "Device not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
