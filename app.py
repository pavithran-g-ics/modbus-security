from flask import Flask, render_template, request, jsonify
from pymodbus.client.sync import ModbusTcpClient
import nmap
import csv

app = Flask(__name__)

# Placeholder for storing Modbus results and protocols
modbus_results = {}
protocols = [{'name': 'Modbus', 'port': 502}]

# Simulate unauthorized access test
def test_unauthorized_access(host):
    success = False
    try:
        # Test unauthorized access by reading a register without proper authentication
        client = ModbusTcpClient(host)
        result = client.read_holding_registers(0, 1)
        client.close()
        success = result is not None
    except:
        success = False
    return success

# Simulate replay attack test
def test_replay_attack(host):
    success = False
    try:
        # Simulate a replay attack by sending the same Modbus command multiple times
        client = ModbusTcpClient(host)
        result = client.read_coils(0, 10)
        if result:
            result_replay = client.read_coils(0, 10)
            client.close()
            success = result == result_replay
    except:
        success = False
    return success

# Simulate data tampering test
def test_data_tampering(host):
    success = False
    try:
        # Simulate data tampering by writing to a coil and comparing the values
        client = ModbusTcpClient(host)
        initial_value = client.read_coils(0, 1).bits[0]
        tampered_value = not initial_value
        client.write_coil(0, tampered_value)
        tampered_result = client.read_coils(0, 1).bits[0]
        client.write_coil(0, initial_value)  # Restore original value
        client.close()
        success = tampered_value == tampered_result
    except:
        success = False
    return success

# Route to run security tests
@app.route('/run_security_tests/<host>', methods=['POST'])
def run_security_tests(host):
    unauthorized_access_result = test_unauthorized_access(host)
    replay_attack_result = test_replay_attack(host)
    data_tampering_result = test_data_tampering(host)

    results = {
        'unauthorized_access': 'Success' if unauthorized_access_result else 'Failure',
        'replay_attack': 'Success' if replay_attack_result else 'Failure',
        'data_tampering': 'Success' if data_tampering_result else 'Failure'
    }
    return jsonify(results)

# Route for Modbus communication
@app.route('/modbus_data/<host>', methods=['GET'])
def modbus_data(host):
    # Simulate fetching Modbus data
    coils = [True, False, True, False, True, False, True, False]
    discrete_inputs = [True, False, True, False]
    holding_registers = [1000, 1500, 2000, 2500]
    input_registers = [500, 750, 1000, 1250]

    return jsonify({
        'coils': coils,
        'discrete_inputs': discrete_inputs,
        'holding_registers': holding_registers,
        'input_registers': input_registers
    })

# Start logging Modbus data
@app.route('/start_logging', methods=['POST'])
def start_logging():
    selected_hosts = request.json.get('selected_hosts')
    # Simulate starting logging for selected hosts
    return jsonify({'message': 'Logging started for ' + ', '.join(selected_hosts)})

# Stop logging Modbus data
@app.route('/stop_logging', methods=['POST'])
def stop_logging():
    return jsonify({'message': 'Logging stopped'})

# Network scanning with Nmap
@app.route('/scan', methods=['POST'])
def scan():
    ip_range = request.form['ip_range']
    selected_protocols = request.form.getlist('selected_protocols')
    nm = nmap.PortScanner()
    protocol_hosts = {}

    # Scan each IP range
    for range in ip_range.split(','):
        nm.scan(hosts=range.strip(), arguments='-p ' + ','.join(selected_protocols))
        for host in nm.all_hosts():
            for proto in selected_protocols:
                if nm[host].has_tcp(int(proto)) and nm[host]['tcp'][int(proto)]['state'] == 'open':
                    if proto not in protocol_hosts:
                        protocol_hosts[proto] = []
                    protocol_hosts[proto].append(host)

    return render_template('scan_results.html', protocols=protocols, protocol_hosts=protocol_hosts)

# Route to display scan results
@app.route('/scan_results')
def scan_results():
    return render_template('scan_results.html', protocols=protocols)

# Home route to display scan page
@app.route('/')
def home():
    return render_template('scan.html', protocols=protocols)

# Modbus testing page
@app.route('/modbus_test/<host>', methods=['GET'])
def modbus_test(host):
    return render_template('modbus_results.html', modbus_results=modbus_results)

if __name__ == '__main__':
    app.run(debug=True)
