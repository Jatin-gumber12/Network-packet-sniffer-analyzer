import eventlet
eventlet.monkey_patch()  # must be FIRST, before Flask imports

from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template("index.html")

# Function to send packets to frontend
def send_packet(packet_data):
    socketio.emit("new_packet", packet_data)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
