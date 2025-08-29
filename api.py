# api.py
from flask import Flask, jsonify
from threading import Thread
from sniffer import start_sniffing, packets_data

app = Flask(__name__)

@app.route("/packets")
def get_packets():
    return jsonify(packets_data)

if __name__ == "__main__":
    # Run sniffer in background thread
    t = Thread(target=start_sniffing, daemon=True)
    t.start()

    # Start Flask API
    app.run(host="0.0.0.0", port=5000, debug=True)
