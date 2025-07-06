from flask import Flask, render_template, request, send_file
import os
import csv
from io import StringIO
from vt_utils import check_hashes, check_ips

app = Flask(__name__)

# Store results for download
latest_results = []

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None, input_type='hash')

@app.route('/scan', methods=['POST'])
def scan():
    global latest_results
    input_type = request.form.get("input_type", "hash")
    input_data = request.form.get("input_data", "")
    file = request.files.get("file_input")

    items = []

    # Read from textarea
    if input_data:
        items = input_data.strip().splitlines()
    # Or read from uploaded file
    elif file:
        file_content = file.read().decode("utf-8")
        items = file_content.strip().splitlines()

    # Remove empty lines and duplicates
    items = list(set(i.strip() for i in items if i.strip()))

    if input_type == "ip":
        results = check_ips(items)
    else:
        results = check_hashes(items)

    latest_results = results
    return render_template("index.html", results=results, input_type=input_type)

@app.route('/download', methods=['GET'])
def download_csv():
    if not latest_results:
        return "No data to download", 400

    output = StringIO()
    writer = csv.writer(output)

    # Dynamic header
    headers = list(latest_results[0].keys())
    writer.writerow(headers)

    for item in latest_results:
        writer.writerow([item.get(h, "") for h in headers])

    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        download_name='vt_results.csv',
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(debug=True)
