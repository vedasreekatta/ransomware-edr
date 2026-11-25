
from flask import Flask, request, render_template_string, send_file
from pathlib import Path
from io import BytesIO
from datetime import datetime
import textwrap

from analysis.static_analysis import basic_file_summary
from analysis.feature_extraction import extract_features
from analysis.behavioral_analysis import analyze_behavior_log
from analysis.risk_assessment import calculate_risk
from preprocessing.file_validation import validate_pe_bytes, sha256_bytes


app = Flask(__name__)
app.secret_key = "querytel-sentinel-local-demo"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "recovered_dashboard.html"

HTML = DASHBOARD_FILE.read_text(encoding="utf-8")

history = []
latest_report_pdf = None


def create_pdf_report(result):
    """Create a basic PDF report using only Python standard libraries."""

    lines = [
        "QUERYTEL SENTINEL",
        "Windows PE File Security Analysis Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "1. FILE INFORMATION",
        f"Filename: {result['filename']}",
        f"File size: {result['size']} bytes",
        f"PE validation: {result['validation']}",
        f"SHA-256: {result['sha256']}",
        "",
        "2. STATIC ANALYSIS",
        f"Entropy: {result['entropy']} / 8.0",
        f"Unique bytes: {result['unique_bytes']} / 256",
        f"Printable ratio: {result['printable_ratio']}",
        f"Null byte ratio: {result['null_byte_ratio']}",
        f"MZ header: {result['mz_header']}",
        f"PE signature: {result['pe_signature']}",
        "",
        "3. BEHAVIORAL ANALYSIS",
        f"Events analyzed: {result['events_analyzed']}",
        f"Indicator count: {result['indicator_count']}",
    ]

    for indicator in result["indicators"]:
        lines.append(f"- {indicator}")

    lines += [
        "",
        "Monitoring status: No live monitoring is implemented.",
        "",
        "4. RISK ASSESSMENT",
        f"Risk level: {result['risk_level']}",
        f"Risk score: {result['risk_score']} / 100",
        f"Reason: {result['risk_reason']}",
        "",
        "5. MACHINE LEARNING STATUS",
        f"Classification: {result['ml_classification']}",
        f"Model note: {result['ml_note']}",
        "",
        "6. SECURITY RECOMMENDATIONS",
        "- Do not run unknown executable files.",
        "- Verify file source and digital signature.",
        "- Use an isolated, authorized analysis lab.",
        "- Keep endpoint protection and OS updates current.",
        "",
        "7. SCOPE AND LIMITATIONS",
        "This report uses static file analysis only.",
        "The uploaded file is not executed.",
        "Live behavioral monitoring is not implemented.",
        "Upload-time ML inference is disabled.",
        "A low risk score does not prove that a file is safe.",
        "",
        "QUERYTEL SENTINEL | LOCAL LAB REPORT",
        "End of report - Local demonstration mode",
    ]

    # Wrap long lines so they fit on an A4 page.
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=88) or [""])

    # Create PDF page streams.
    pages = [wrapped[i:i + 48] for i in range(0, len(wrapped), 48)]
    objects = []

    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append("")  # Pages object filled below.
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_refs = []

    for page_lines in pages:
        page_number = len(page_refs) + 1
        content = ["BT", "/F1 9 Tf", "45 800 Td", "13 TL"]

        for line in page_lines:
            safe_line = line.encode("ascii", errors="replace").decode("ascii")
            safe_line = safe_line.replace("\\", "\\\\")
            safe_line = safe_line.replace("(", "\\(").replace(")", "\\)")
            content.append(f"({safe_line}) Tj")
            content.append("T*")

        content.append("ET")
        stream = "\n".join(content).encode("ascii")

        page_obj = len(objects) + 1
        stream_obj = page_obj + 1

        objects.append(
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> "
            f"/Contents {stream_obj} 0 R >>"
        )
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n"
            + stream.decode("ascii")
            + "\nendstream"
        )
        page_refs.append(f"{page_obj} 0 R")

    objects[1] = (
        "<< /Type /Pages /Kids ["
        + " ".join(page_refs)
        + f"] /Count {len(page_refs)} >>"
    )

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]

    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj.encode("ascii"))
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")

    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF".encode("ascii")
    )

    return bytes(pdf)


@app.route("/", methods=["GET", "POST"])
def dashboard():
    global latest_report_pdf

    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            error = "Please select a file."
        elif Path(uploaded.filename).suffix.lower() not in {".exe", ".dll"}:
            error = "Only EXE and DLL files are allowed."
        else:
            data = uploaded.read()

            if not data:
                error = "Empty file selected."
            else:
                pe_valid, validation_message = validate_pe_bytes(data)

                if not pe_valid:
                    error = validation_message
                else:
                    features = extract_features(data)
                    behavior = analyze_behavior_log([])

                    risk = calculate_risk(
                        model_score=None,
                        behavioral_indicators=behavior["indicators"]
                    )

                    result = {
                        "filename": Path(uploaded.filename).name,
                        "size": len(data),
                        "sha256": sha256_bytes(data),
                        "validation": validation_message,
                        "entropy": features["entropy"],
                        "unique_bytes": features["unique_bytes"],
                        "printable_ratio": features["printable_ratio"],
                        "null_byte_ratio": features["null_byte_ratio"],
                        "mz_header": features["mz_header"],
                        "pe_signature": features["pe_signature"],
                        "events_analyzed": behavior["events_analyzed"],
                        "indicators": behavior["indicators"],
                        "indicator_count": behavior["indicator_count"],
                        "risk_level": risk["risk_level"],
                        "risk_score": risk["score"],
                        "risk_reason": risk["reason"],
                        "ml_classification": "Not evaluated",
                        "ml_note": (
                            "Upload inference is disabled until API-related "
                            "features match the training dataset. Dataset "
                            "metrics are not real-world detection guarantees."
                        )
                    }

                    latest_report_pdf = create_pdf_report(result)

                    history.insert(0, result.copy())
                    del history[10:]

    return render_template_string(
        HTML,
        result=result,
        error=error,
        history=history
    )


@app.route("/download-report")
def download_report():
    if latest_report_pdf is None:
        return "No report available. Analyze a valid PE file first.", 404

    return send_file(
        BytesIO(latest_report_pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="QueryTel_Sentinel_Report.pdf"
    )


@app.route("/health")
def health():
    return {"status": "running", "application": "QueryTel Sentinel"}


@app.errorhandler(413)
def file_too_large(error):
    return "File is too large. Maximum upload size is 20 MB.", 413


if __name__ == "__main__":
    print("Starting QueryTel Sentinel...")
    print("Open http://127.0.0.1:5000 in your browser.")
    app.run(debug=False, host="127.0.0.1", port=5000)

