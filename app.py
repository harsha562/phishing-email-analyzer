from flask import Flask, render_template, request, flash, redirect, url_for
from analyzer import analyze_email
import os

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_content = None

    # Option 1: file upload
    uploaded_file = request.files.get("eml_file")
    if uploaded_file and uploaded_file.filename:
        raw_content = uploaded_file.read()

    # Option 2: pasted raw text
    pasted_text = request.form.get("raw_text", "").strip()
    if not raw_content and pasted_text:
        raw_content = pasted_text

    if not raw_content:
        flash("Please upload a .eml file or paste raw email content.")
        return redirect(url_for("index"))

    try:
        result = analyze_email(raw_content)
    except Exception as e:
        flash(f"Could not parse this email: {e}")
        return redirect(url_for("index"))

    return render_template("result.html", result=result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
