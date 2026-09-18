import json
import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv

# NEW: Import the updated SDK
from google import genai 

load_dotenv()

app = Flask(__name__)

# NEW: Initialize the GenAI client with the updated SDK
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# UPGRADED PROMPT: Asking for an array for the mitigation steps
SYSTEM_PROMPT = (
    'You are an expert SIEM cybersecurity analyst. Analyze these server logs. Find the breach. '
    'You MUST respond ONLY in valid JSON format. Do not use markdown blocks like ```json. '
    'Use exactly this structure: '
    '{ '
        '"ip": "The attacker\'s IP", '
        '"vector": "The attack method (e.g., SQL Injection)", '
        '"score": 9.5, '
        '"mitigation": [ '
            '"[CRITICAL] Step 1...", '
            '"[ACTION] Step 2...", '
            '"[INFO] Step 3..." '
        '] '
    '}'
)


def init_db():
    connection = sqlite3.connect("siem.db")
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                ip TEXT,
                vector TEXT,
                score REAL,
                mitigation TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
            """
        )
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(alerts)")
        }
        if "status" not in columns:
            connection.execute(
                "ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'active'"
            )
        connection.commit()
    finally:
        connection.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    # FROM COPILOT: Excellent check for missing files
    file = request.files.get("file")
    if file is None or file.filename == "":
        return jsonify({"error": "No file was sent."}), 400

    # FROM COPILOT: Excellent check to make sure it's actually a text file
    try:
        log_text = file.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "The uploaded file must be a UTF-8 text file."}), 400

    try:
        contents = f"{SYSTEM_PROMPT}\n\nLogs:\n{log_text}"
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=contents,
            )
        except Exception as error:
            error_code = getattr(error, "code", None) or getattr(error, "status_code", None)
            error_text = str(error).upper()
            is_unavailable = (
                error_code == 503
                or "503" in error_text
                or "UNAVAILABLE" in error_text
            )
            if not is_unavailable:
                raise

            response = client.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=contents,
            )
        
        # NEW: Clean the response in case Gemini adds markdown backticks
        cleaned_json = response.text.replace('```json', '').replace('```', '').strip()
        
        # FROM COPILOT: Safely load the JSON
        result = json.loads(cleaned_json)
        
    except json.JSONDecodeError:
        return jsonify({"error": "Gemini returned invalid JSON."}), 502
    except Exception as error:
        return jsonify({"error": str(error)}), 500

    connection = sqlite3.connect("siem.db")
    try:
        connection.execute(
            """
            INSERT INTO alerts (ip, vector, score, mitigation, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                result.get("ip"),
                result.get("vector"),
                result.get("score"),
                json.dumps(result.get("mitigation", [])),
                "active",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    connection = sqlite3.connect("siem.db")
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC"
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        connection.close()


@app.route("/api/resolve/<int:alert_id>", methods=["POST"])
def resolve_alert(alert_id):
    connection = sqlite3.connect("siem.db")
    try:
        cursor = connection.execute(
            "UPDATE alerts SET status = 'resolved' WHERE id = ?",
            (alert_id,),
        )
        connection.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Alert not found."}), 404
        return jsonify({"message": "Alert resolved.", "id": alert_id})
    finally:
        connection.close()


@app.route("/api/resolve_all", methods=["POST"])
def resolve_all():
    connection = sqlite3.connect("siem.db")
    try:
        cursor = connection.execute(
            "UPDATE alerts SET status = 'resolved' WHERE status != 'resolved'"
        )
        connection.commit()
        return jsonify({"message": "All alerts resolved.", "updated": cursor.rowcount})
    finally:
        connection.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)