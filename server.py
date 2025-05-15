from flask import Flask, request, jsonify
import sqlite3
import os
import base64
import uuid

app = Flask(__name__)
DB_PATH = "qr_codes.db"
STORAGE_PATH = "qr_storage"

# Ensure storage directory exists
if not os.path.exists(STORAGE_PATH):
    os.makedirs(STORAGE_PATH)

# Initialize database
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS qr_codes (
                hash TEXT PRIMARY KEY,
                filename TEXT,
                data TEXT,
                image_path TEXT
            )
        """)
        conn.commit()

@app.route('/upload', methods=['POST'])
def upload_qr():
    try:
        data = request.json
        qr_hash = data['hash']
        filename = data['filename']
        qr_data = data['data']
        image_data = base64.b64decode(data['image'])
        
        # Save image to storage
        image_path = os.path.join(STORAGE_PATH, f"{uuid.uuid4().hex}.png")
        with open(image_path, "wb") as f:
            f.write(image_data)
        
        # Store metadata in database
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO qr_codes (hash, filename, data, image_path) VALUES (?, ?, ?, ?)",
                (qr_hash, filename, qr_data, image_path)
            )
            conn.commit()
        
        return jsonify({"status": "success", "hash": qr_hash}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_qr/<hash>', methods=['GET'])
def get_qr(hash):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename, data, image_path FROM qr_codes WHERE hash = ?", (hash,))
            result = cursor.fetchone()
            if result:
                filename, data, image_path = result
                with open(image_path, "rb") as f:
                    image_data = base64.b64encode(f.read()).decode('utf-8')
                return jsonify({
                    "filename": filename,
                    "data": data,
                    "hash": hash,
                    "image": image_data
                }), 200
            else:
                return jsonify({"error": "QR code not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)