import json
import os

import google.generativeai as genai
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

app = Flask(__name__)

SYSTEM_PROMPT = (
	'Analyze this server log. Identify the attacker IP, the attack vector '
	'(e.g., SQL Injection, Brute Force), a severity score from 1.0 to 10.0, '
	'and a short mitigation strategy. You MUST return ONLY a valid JSON object '
	'with the exact keys: "ip", "vector", "score", and "mitigation". Do not '
	'include markdown formatting or backticks.'
)


@app.route("/")
def index():
	return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
	file = request.files.get("file")
	if file is None or file.filename == "":
		return jsonify({"error": "No file was sent."}), 400

	try:
		log_text = file.read().decode("utf-8")
	except UnicodeDecodeError:
		return jsonify({"error": "The uploaded file must be a UTF-8 text file."}), 400

	try:
		model = genai.GenerativeModel(
			model_name="gemini-3.8-flash",
			system_instruction=SYSTEM_PROMPT,
		)
		response = model.generate_content(log_text)
		result = json.loads(response.text)
	except json.JSONDecodeError:
		return jsonify({"error": "Gemini returned invalid JSON."}), 502
	except Exception as error:
		return jsonify({"error": str(error)}), 500

	return jsonify(result)


if __name__ == "__main__":
	app.run(debug=True, port=5000)
