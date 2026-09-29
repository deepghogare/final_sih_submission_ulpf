import urllib.request, json

boundary = b'----boundary12345'

def upload_file(filename, filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    body = b'--' + boundary + b'\r\n'
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b'Content-Type: text/plain\r\n\r\n'
    body += data + b'\r\n'
    body += b'--' + boundary + b'--\r\n'
    req = urllib.request.Request('http://localhost:8000/api/v1/process', data=body)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary.decode()}')
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    print(f'{filename}: {result["events_processed"]} events processed')

upload_file('sample_security_traffic.cef', 'test_data/sample_security_traffic.cef')
upload_file('sample_network_syslog.log', 'test_data/sample_network_syslog.log')
upload_file('sample_cloud_audit.json', 'test_data/sample_cloud_audit.json')
upload_file('sample_acme_guard.ndjson', 'test_data/sample_acme_guard.ndjson')
import glob, os
for p in sorted(glob.glob('demo_logs_for_upload/*')):
    upload_file(os.path.basename(p), p)

r = urllib.request.urlopen('http://localhost:8000/api/v1/dashboard/stats')
stats = json.loads(r.read())
print('\nDashboard stats:', stats['total_events'], 'total events')

r2 = urllib.request.urlopen('http://localhost:8000/api/v1/blockchain/blocks?limit=5')
blk = json.loads(r2.read())
print('Blockchain blocks:', len(blk['blocks']), 'blocks')
