import json
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime

import boto3
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv
from fpdf import FPDF

# NEW: Import the updated SDK
from google import genai 

load_dotenv()

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET_NAME = os.environ.get("AWS_BUCKET_NAME")

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


def generate_and_upload_pdf(ip, vector, score, mitigation, log_text):
    incident_id = uuid.uuid4().hex[:8].upper()
    analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    temporary_folder = tempfile.mkdtemp()
    safe_ip = "".join(character if character.isalnum() or character in ".-_" else "_" for character in str(ip))
    pdf_path = os.path.join(temporary_folder, f"incident_{safe_ip}.pdf")
    evidence_path = os.path.join(temporary_folder, f"Incident_{incident_id}_Evidence.txt")

    def pdf_text(value):
        return str(value).encode("latin-1", "replace").decode("latin-1")

    def add_section_heading(pdf, title):
        pdf.set_fill_color(31, 78, 121)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, title, ln=1, fill=True)
        pdf.ln(2)
        pdf.set_text_color(0, 0, 0)

    try:
        pdf = FPDF()
        pdf.set_title("Sentinel SIEM - Automated Incident Report")
        pdf.set_author("Sentinel SIEM")
        pdf.add_page()

        pdf.set_text_color(153, 0, 0)
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "CONFIDENTIAL: SENTINEL SIEM - AUTOMATED INCIDENT REPORT", ln=1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        add_section_heading(pdf, "Metadata")
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 7, f"Date/Time of Analysis: {analysis_time}", ln=1)
        pdf.cell(0, 7, f"Incident ID: {incident_id}", ln=1)
        pdf.ln(5)

        severity_label = (
            "High" if float(score or 0) >= 7
            else "Medium" if float(score or 0) >= 4
            else "Low"
        )
        add_section_heading(pdf, "Executive Summary")
        pdf.set_font("Arial", size=12)
        summary = (
            f"A {severity_label} severity incident involving {vector} was detected "
            f"with a score of {score} out of 10. The activity requires review of the "
            "listed indicators and execution of the recommended mitigation playbook."
        )
        pdf.multi_cell(0, 7, pdf_text(summary))
        pdf.ln(5)

        add_section_heading(pdf, "Indicators of Compromise (IOCs)")
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 7, f"Attacker IP: {pdf_text(ip)}", ln=1)
        pdf.ln(5)

        add_section_heading(pdf, "Mitigation & Playbook")
        pdf.set_font("Arial", size=12)
        mitigation_steps = mitigation if isinstance(mitigation, list) else [mitigation]
        for step in mitigation_steps:
            pdf.multi_cell(0, 7, pdf_text(f"- {step}"))

        pdf.output(pdf_path)
        with open(evidence_path, "w", encoding="utf-8") as evidence_file:
            evidence_file.write(log_text)

        s3 = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        s3.upload_file(
            pdf_path,
            AWS_BUCKET_NAME,
            f"incidents/Incident_{incident_id}_Report.pdf",
            ExtraArgs={"ContentType": "application/pdf"},
        )
        s3.upload_file(
            evidence_path,
            AWS_BUCKET_NAME,
            f"incidents/Incident_{incident_id}_Evidence.txt",
            ExtraArgs={"ContentType": "text/plain"},
        )
    finally:
        for path in (pdf_path, evidence_path):
            if os.path.exists(path):
                os.remove(path)
        if os.path.isdir(temporary_folder):
            os.rmdir(temporary_folder)


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

    generate_and_upload_pdf(
        result.get("ip"),
        result.get("vector"),
        result.get("score"),
        result.get("mitigation", []),
        log_text,
    )

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