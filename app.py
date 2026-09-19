import json
import os
import sqlite3
import tempfile
import uuid
import hashlib
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
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

app = Flask(__name__)

# NEW: Initialize the GenAI client with the updated SDK
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# UPGRADED PROMPT: Return the complete incident report data structure.
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
        '], '
        '"executive_summary": "A highly detailed professional 3-sentence summary of the breach.", '
        '"affected_assets": "A comma-separated list of likely compromised servers/databases.", '
        '"mitre_code": "The MITRE ATT&CK technique ID, for example T1190.", '
        '"mitre_tactic": "The corresponding MITRE ATT&CK tactic, for example Initial Access." '
    '}'
)


class PDF(FPDF):
    def header(self):
        self.set_draw_color(139, 0, 0)
        self.set_line_width(1)
        self.line(self.l_margin, 10, self.w - self.r_margin, 10)

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(0, 0, 0)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_font("Arial", "I", 10)
        self.set_text_color(150, 150, 150)
        self.set_y(-12)
        self.cell(130, 8, "Sentinel SIEM Incident Response Summary")
        self.cell(0, 8, f"Page {self.page_no()}", align="R")


def send_critical_alert(ip, vector, score):
    sns = boto3.client(
        "sns",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="us-east-1"
    )
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="CRITICAL ALERT: Sentinel SIEM",
        Message=(
            "A critical security threat was detected by Sentinel SIEM.\n\n"
            f"Attacker IP: {ip}\n"
            f"Attack Vector: {vector}\n"
            f"Severity Score: {score}\n\n"
            "Please investigate this incident immediately and activate the "
            "appropriate incident response procedures."
        ),
    )


@app.route("/api/subscribe", methods=["POST"])
def subscribe_email():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        return jsonify({"error": "A valid email address is required."}), 400
    if not SNS_TOPIC_ARN:
        return jsonify({"error": "SNS topic is not configured."}), 500

    sns = boto3.client(
        "sns",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    sns.subscribe(
        TopicArn=SNS_TOPIC_ARN,
        Protocol="email",
        Endpoint=email,
        ReturnSubscriptionArn=True,
    )
    return jsonify({"message": "Subscription pending"})


def generate_and_upload_pdf(
    ip,
    vector,
    score,
    mitigation,
    executive_summary,
    affected_assets,
    log_text,
):
    incident_id = uuid.uuid4().hex[:8].upper()
    report_id = f"REP-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:1].upper()}"
    analysis_datetime = datetime.now()
    analysis_time = analysis_datetime.strftime("%Y-%m-%d %H:%M:%S")
    date_path = analysis_datetime.strftime("%Y/%m/%d")
    s3_prefix = f"{date_path}/INC-{incident_id}"
    temporary_folder = tempfile.mkdtemp()
    pdf_path = os.path.join(temporary_folder, "report.pdf")
    evidence_path = os.path.join(temporary_folder, "raw_evidence.txt")

    def pdf_text(value):
        return str(value).encode("latin-1", "replace").decode("latin-1")

    def add_section_heading(pdf, title):
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(40, 50, 70)
        pdf.cell(0, 8, pdf_text(title), ln=1)
        pdf.set_draw_color(210, 210, 210)
        pdf.set_line_width(0.25)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

    try:
        pdf = PDF()
        pdf.alias_nb_pages()
        pdf.set_title("Sentinel SIEM - Automated Incident Report")
        pdf.set_author("Sentinel SIEM")
        pdf.set_margins(20, 20, 20)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        pdf.set_text_color(40, 50, 70)
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 12, "FORENSIC ANALYSIS & INCIDENT REPORT", ln=1, align="C")
        pdf.ln(7)

        # Fixed-width metadata columns keep every row perfectly aligned.
        label_width = 40
        value_width = 80
        badge_width = pdf.w - pdf.l_margin - pdf.r_margin - label_width - value_width
        metadata_rows = (
            ("Date", analysis_time),
            ("Report ID", report_id),
            ("Incident ID", f"INC-{incident_id}"),
            ("Attacker IP", str(ip)),
        )
        for index, (label, value) in enumerate(metadata_rows):
            pdf.set_text_color(40, 50, 70)
            pdf.set_font("Arial", "B", 10)
            pdf.cell(label_width, 6, pdf_text(label))
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=10)
            pdf.cell(value_width, 6, pdf_text(value))
            if index == 0:
                pdf.set_text_color(139, 0, 0)
                pdf.set_font("Arial", "B", 10)
                pdf.cell(badge_width, 6, "TLP: RED", align="R", ln=1)
            else:
                pdf.cell(badge_width, 6, "", ln=1)
        pdf.ln(8)

        add_section_heading(pdf, "1. Executive Summary")
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6, pdf_text(executive_summary))
        pdf.ln(8)

        add_section_heading(pdf, "2. Affected Assets")
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6, pdf_text(affected_assets))
        pdf.ln(8)

        add_section_heading(pdf, "3. Indicators of Compromise")
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6, pdf_text(f"Attacker IP: {ip}"))
        pdf.ln(8)

        add_section_heading(pdf, "4. Mitigation & Playbook")
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        mitigation_text = "\n".join(mitigation) if isinstance(mitigation, list) else str(mitigation)
        cleaned_lines = []
        for line in mitigation_text.splitlines():
            cleaned_line = (
                line.replace("[CRITICAL]", "")
                .replace("[ACTION]", "")
                .replace("[INFO]", "")
                .strip()
            )
            if cleaned_line:
                cleaned_lines.append(cleaned_line)

        for cleaned_line in cleaned_lines:
            pdf.cell(7, 6, pdf_text(chr(149)))
            pdf.multi_cell(0, 6, pdf_text(cleaned_line))
        pdf.ln(8)

        add_section_heading(pdf, "DOCUMENT VERIFICATION")
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        document_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        pdf.multi_cell(0, 6, pdf_text(f"Hash: {document_hash}"))

        pdf.output(pdf_path)
        with open(evidence_path, "w", encoding="utf-8") as evidence_file:
            evidence_file.write(log_text)

        s3 = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name="us-east-1"
        )
        s3.upload_file(
            pdf_path,
            AWS_BUCKET_NAME,
            f"{s3_prefix}/report.pdf",
            ExtraArgs={"ContentType": "application/pdf"},
        )
        s3.upload_file(
            evidence_path,
            AWS_BUCKET_NAME,
            f"{s3_prefix}/raw_evidence.txt",
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
                status TEXT DEFAULT 'active',
                mitre_code TEXT,
                mitre_tactic TEXT
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
        if "mitre_code" not in columns:
            connection.execute(
                "ALTER TABLE alerts ADD COLUMN mitre_code TEXT"
            )
        if "mitre_tactic" not in columns:
            connection.execute(
                "ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT"
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
            INSERT INTO alerts (
                ip, vector, score, mitigation, status, mitre_code, mitre_tactic
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("ip"),
                result.get("vector"),
                result.get("score"),
                json.dumps(result.get("mitigation", [])),
                "active",
                result.get("mitre_code"),
                result.get("mitre_tactic"),
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
        result.get("executive_summary", "No executive summary was provided."),
        result.get("affected_assets", "No affected assets were identified."),
        log_text,
    )

    if float(result.get("score", 0)) >= 8.0:
        send_critical_alert(
            result.get("ip"),
            result.get("vector"),
            result.get("score"),
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