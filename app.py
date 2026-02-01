from flask import Flask, render_template, request, jsonify
from backend.generator import lcg_generate, find_period
from backend.cesaro_test import cesaro_test
from backend.md5_hash import hash_string, hash_file, verify_file
from backend.rc5 import decrypt_file_rc5, encrypt_file_rc5
from backend.rsa import encrypt_file_rsa, decrypt_file_rsa, generate_rsa_keys
import os
from backend.dss import generate_dss_keys, dss_sign, dss_verify

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("menu.html")

@app.route("/lab1")
def lab1():
    return render_template("lab1.html")

@app.route("/lab2")
def lab2():
    return render_template("lab2.html")

@app.route("/lab3")
def lab3():
    return render_template("lab3.html")

@app.route("/lab4")
def lab4():
    return render_template("lab4.html")

@app.route("/lab5")
def lab5():
    return render_template("lab5.html")

@app.route("/rc5_encrypt", methods=["POST"])
def rc5_encrypt():
    if "file" not in request.files:
        return jsonify({"error": "Файл не завантажено"})
    file = request.files["file"]
    password = request.form.get("password")

    if not password:
        return jsonify({"error": "Введіть парольну фразу"})

    input_path = os.path.join("output", file.filename)
    os.makedirs("output", exist_ok=True)
    file.save(input_path)

    output_filename = f"enc_{file.filename}"
    output_path = os.path.join("output", output_filename)

    try:
        encrypt_file_rc5(input_path, output_path, password)
        return jsonify({
            "message": "Файл успішно зашифровано!",
            "filename": output_filename,
            "path": output_path
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/rc5_decrypt", methods=["POST"])
def rc5_decrypt():
    if "file" not in request.files:
        return jsonify({"error": "Файл не завантажено"})
    file = request.files["file"]
    password = request.form.get("password")

    if not password:
        return jsonify({"error": "Введіть парольну фразу"})

    input_path = os.path.join("output", file.filename)
    os.makedirs("output", exist_ok=True)
    file.save(input_path)

    original_name = file.filename.replace("enc_", "dec_")
    output_path = os.path.join("output", original_name)

    try:
        decrypt_file_rc5(input_path, output_path, password)
        return jsonify({
            "message": "Файл успішно розшифровано!",
            "filename": original_name,
            "path": output_path
        })
    except ValueError:
        return jsonify({"error": "Помилка: Невірний пароль або файл пошкоджено."})
    except Exception as e:
        return jsonify({"error": f"Системна помилка: {str(e)}"})

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    a, c, m, x0, n = data["a"], data["c"], data["m"], data["x0"], data["n"]
    seq = lcg_generate(a, c, m, x0, n)
    return jsonify({"sequence": seq})

@app.route("/save_sequence", methods=["POST"])
def save_sequence():
    data = request.get_json()
    sequence = data["sequence"]
    filepath = data["filepath"]
    params_str = data["paramsStr"]

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(params_str + "\n")
            for i, num in enumerate(sequence, 1):
                f.write(f"{i}. {num}\n")
        return jsonify({"message": f"Послідовність збережено у файл: {filepath}"})
    except Exception as e:
        return jsonify({"message": f"Помилка збереження файлу: {str(e)}"})

@app.route("/period", methods=["POST"])
def period():
    data = request.get_json()
    a, c, m, x0 = data["a"], data["c"], data["m"], data["x0"]
    period = find_period(a, c, m, x0)
    return jsonify({"period": period})

@app.route("/cesaro", methods=["POST"])
def cesaro():
    data = request.get_json()
    a, c, m, x0, samples = data["a"], data["c"], data["m"], data["x0"], data["samples"]
    pi_est, prob = cesaro_test(samples, a, c, m, x0)
    return jsonify({"pi_est": pi_est, "prob": prob})

@app.route("/hash_string", methods=["POST"])
def hash_string_route():
    data = request.get_json()
    input_str = data["input"]
    hash_result = hash_string(input_str)
    return jsonify({"hash": hash_result})

@app.route("/hash_file", methods=["POST"])
def hash_file_route():
    if "file" not in request.files:
        return jsonify({"error": "Файл не завантажено"})
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Назва файлу порожня"})

    filepath = os.path.join("output", file.filename)
    os.makedirs("output", exist_ok=True)
    file.save(filepath)
    hash_result = hash_file(filepath)

    return jsonify({
        "hash": hash_result,
        "filepath": filepath,
        "filename": file.filename
    })

@app.route("/verify_file", methods=["POST"])
def verify_file_route():
    data = request.get_json()
    filepath = data["filepath"]
    expected_hash = data["expected_hash"]
    is_valid = verify_file(filepath, expected_hash)
    return jsonify({"is_valid": is_valid})

@app.route("/save_hash", methods=["POST"])
def save_hash():
    data = request.get_json()
    hash_value = data["hash"]
    filepath = data["filepath"]
    input_str = data.get("input_str")

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            if input_str:
                f.write(f"Hash for string: {input_str}\n")
            f.write(f"{hash_value}\n")
        return jsonify({"message": f"Хеш збережено у файл: {filepath}"})
    except Exception as e:
        return jsonify({"message": f"Помилка збереження файлу: {str(e)}"})


@app.route("/rsa_gen_keys", methods=["POST"])
def rsa_gen_keys():
    try:
        priv_pem, pub_pem = generate_rsa_keys()
        return jsonify({
            "private_key": priv_pem.decode('utf-8'),
            "public_key": pub_pem.decode('utf-8')
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/rsa_action", methods=["POST"])
def rsa_action():
    action = request.form.get("action")
    custom_path = request.form.get("custom_path")

    if "file" not in request.files:
        return jsonify({"error": "Файл не завантажено"})

    file = request.files["file"]
    key_pem = request.form.get("key")

    if not key_pem:
        return jsonify({"error": "Ключ не надано"})

    if not custom_path:
        return jsonify({"error": "Шлях збереження не вказано"})

    if not file.filename:
        return jsonify({"error": "Файл не вибрано"})

    input_path = os.path.join("output", file.filename)
    os.makedirs("output", exist_ok=True)
    file.save(input_path)

    try:
        directory = os.path.dirname(custom_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        key_bytes = key_pem.encode('utf-8')

        if action == "encrypt":
            encrypt_file_rsa(input_path, custom_path, key_bytes)
            msg = "Файл зашифровано RSA і збережено!"

        elif action == "decrypt":
            decrypt_file_rsa(input_path, custom_path, key_bytes)
            msg = "Файл розшифровано RSA і збережено!"
        else:
            return jsonify({"error": "Невідома дія"})

        return jsonify({
            "message": msg,
            "filename": os.path.basename(custom_path),
            "path": custom_path
        })

    except ValueError:
        return jsonify({"error": "Помилка ключа або даних. Перевірте правильність ключа."})
    except Exception as e:
        return jsonify({"error": f"Помилка: {str(e)}"})

@app.route("/dss_gen_keys", methods=["POST"])
def dss_gen_keys_route():
    try:
        priv, pub = generate_dss_keys()
        return jsonify({
            "private_key": priv.decode('utf-8'),
            "public_key": pub.decode('utf-8')
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/dss_sign", methods=["POST"])
def dss_sign_route():
    data_source = request.form.get("source")
    priv_key = request.form.get("private_key")

    if not priv_key:
        return jsonify({"error": "Приватний ключ обов'язковий"})

    data_bytes = b""

    if data_source == "text":
        text = request.form.get("text_input", "")
        data_bytes = text.encode('utf-8')
    elif data_source == "file":
        if "file" not in request.files:
            return jsonify({"error": "Файл не завантажено"})
        file = request.files["file"]
        data_bytes = file.read()

    else:
        return jsonify({"error": "Невідоме джерело даних"})

    try:
        signature = dss_sign(data_bytes, priv_key.encode('utf-8'))
        return jsonify({"signature": signature})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/dss_verify", methods=["POST"])
def dss_verify_route():
    verify_type = request.form.get("verify_type")
    pub_key = request.form.get("public_key")
    signature_hex = request.form.get("signature")

    if "signature_file" in request.files and request.files["signature_file"].filename != "":
        sig_file = request.files["signature_file"]
        signature_hex = sig_file.read().decode('utf-8').strip()

    if not pub_key:
        return jsonify({"error": "Публічний ключ обов'язковий"})
    if not signature_hex:
        return jsonify({"error": "Підпис відсутній"})

    data_bytes = b""

    if verify_type == "text":
        text = request.form.get("text_input", "")
        data_bytes = text.encode('utf-8')
    elif verify_type == "file":
        if "file" not in request.files:
            return jsonify({"error": "Файл даних не завантажено"})
        file = request.files["file"]
        data_bytes = file.read()
    else:
        return jsonify({"error": "Невідомий тип перевірки"})

    is_valid = dss_verify(data_bytes, signature_hex, pub_key.encode('utf-8'))

    return jsonify({
        "valid": is_valid,
        "message": "Підпис ВІРНИЙ!" if is_valid else "Підпис НЕВІРНИЙ!"
    })


@app.route("/save_signature_file", methods=["POST"])
def save_signature_file():
    data = request.get_json()
    sig = data.get("signature")
    filename = data.get("filename", "signature.txt")
    path = os.path.join("output", filename)
    os.makedirs("output", exist_ok=True)

    with open(path, "w") as f:
        f.write(sig)

    return jsonify({"message": f"Збережено у {path}"})


@app.route("/save_signature_local", methods=["POST"])
def save_signature_local():
    data = request.get_json()
    signature_text = data.get("signature")
    filename = data.get("filename", "signature.txt")

    if not signature_text:
        return jsonify({"error": "Немає підпису для збереження!", "status": "error"})

    return jsonify({
        "message": "Готово для завантаження",
        "status": "success",
        "filename": filename,
        "signature": signature_text
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)