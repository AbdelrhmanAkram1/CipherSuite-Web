from flask import Flask, render_template, request, jsonify, session
import Logic as core
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)   # for session storage of RSA keys


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    data = request.json
    bits = int(data.get("bits", 2048))
    try:
        private_pem, public_pem = core.generate_rsa_keys(bits)
        session["private_key"] = private_pem
        session["public_key"]  = public_pem
        return jsonify({
            "private_key": private_pem,
            "public_key":  public_pem
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/process", methods=["POST"])
def process():
    data   = request.json
    mode   = data.get("mode")
    algo   = data.get("algo")
    text   = data.get("text", "")
    key    = data.get("key", "")
    action = data.get("action")

    try:
        # ── SYMMETRIC ──────────────────────────
        if mode == "Symmetric":
            if action == "encrypt":
                result = core.symmetric_encrypt(algo, key, text)
            else:
                result = core.symmetric_decrypt(algo, key, text)
            return jsonify({"result": result})

        # ── ASYMMETRIC ─────────────────────────
        elif mode == "Asymmetric":
            pub  = data.get("public_key")  or session.get("public_key")
            priv = data.get("private_key") or session.get("private_key")
            if action == "encrypt":
                result = core.asymmetric_encrypt(pub, text)
            else:
                result = core.asymmetric_decrypt(priv, text)
            return jsonify({"result": result})

        # ── ENCODING ───────────────────────────
        elif mode == "Encoding":
            if action == "encode":
                result = core.encode_data(algo, text)
            else:
                result = core.decode_data(algo, text)
            return jsonify({"result": result})

        # ── HASHING ────────────────────────────
        elif mode == "Hashing":
            digest, salt_hex = core.hash_data(algo, text, key)
            return jsonify({"result": digest, "salt": salt_hex})

    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)
