import base64

from flask import Flask, render_template, request, jsonify

from src.authentication import authenticate_email
from src.dkim_checker import generate_keys, sign_email

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/demo-email")
def demo_email():
    try:
        generate_keys()

        email = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Gateway Security Demo\r\n"
            b"\r\n"
            b"This is a controlled email authentication test.\r\n"
        )

        signed = sign_email(email, "example.com", "test")

        return jsonify({
            "success": True,
            "email": signed.decode("ascii"),
            "email_b64": base64.b64encode(signed).decode("ascii")
        })

    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@app.post("/api/analyze")
def analyze_email():
    try:
        data = request.get_json(force=True)

        if data.get("email_b64"):
            raw_email = base64.b64decode(
                data["email_b64"],
                validate=True
            )
        else:
            raw_email = data.get("email", "").encode("utf-8")

        if not raw_email:
            return jsonify({
                "success": False,
                "error": "Please provide an email."
            }), 400

        result = authenticate_email(
            raw_email=raw_email,
            client_ip=data.get("client_ip", ""),
            mail_from_domain=data.get(
                "mail_from_domain", ""
            ),
            spf_record=data.get("spf_record", ""),
            dmarc_record=data.get("dmarc_record", "")
        )

        return jsonify({
            "success": True,
            "results": result
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 400


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
