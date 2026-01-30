function getLCGParams() {
    return {
        a: parseInt(document.getElementById("a").value),
        c: parseInt(document.getElementById("c").value),
        m: parseInt(document.getElementById("m").value),
        x0: parseInt(document.getElementById("x0").value)
    };
}

async function generate() {
    const params = getLCGParams();
    const n = parseInt(document.getElementById("n").value);

    if (isNaN(n) || n <= 0) {
        document.getElementById("output-seq").textContent = "Введіть коректну кількість чисел (n).";
        return;
    }

    const data = { ...params, n: n };

    const res = await fetch("/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
    const result = await res.json();
    const displaySeq = result.sequence.slice(0, 100).join("\n") +
                       (result.sequence.length > 100 ? "\n..." : "");

    document.getElementById("output-seq").textContent = displaySeq;
    document.getElementById("save-section").style.display = "block";
    window.generatedSequence = result.sequence;
    window.sequenceParams = params;
    window.n = n;
}

async function saveSequence() {
    const filepath = document.getElementById("filepath").value;
    if (!filepath) {
        alert("Введіть шлях до файлу!");
        return;
    }

    const params = window.sequenceParams;
    const n = window.n;
    const sequence = window.generatedSequence;

    const paramsStr = `Parameters: a=${params.a}, c=${params.c}, m=${params.m}, x0=${params.x0}, n=${n}`;

    const res = await fetch("/save_sequence", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sequence, filepath, paramsStr })
    });
    const result = await res.json();
    alert(result.message);
}

async function findPeriod() {
    const params = getLCGParams();

    const res = await fetch("/period", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params)
    });
    const result = await res.json();

    document.getElementById("output-period").textContent = `Період послідовності: ${result.period}`;
}

async function cesaro() {
    const params = getLCGParams();
    const samples = parseInt(document.getElementById("samples").value);

    if (isNaN(samples) || samples <= 0) {
        document.getElementById("output-cesaro").textContent = "Введіть коректну кількість пар (samples).";
        return;
    }

    const data = { ...params, samples: samples };

    document.getElementById("output-cesaro").textContent = "Виконується тест Чезаро...";

    const res = await fetch("/cesaro", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
    const result = await res.json();

    document.getElementById("output-cesaro").textContent =
        `Оцінка π: ${result.pi_est.toFixed(6)}\nЙмовірність взаємної простоти: ${result.prob.toFixed(6)}`;
}

async function saveHash(type) {
    let hash, filepathInputId, input_str = null, file_info = null;

    if (type === 'string') {
        hash = document.getElementById("output-hash-string").textContent;
        filepathInputId = "save-path-string";
        input_str = document.getElementById("input-string").value;
    } else if (type === 'file') {
        if (!window.fileHashData) {
            alert("Спочатку обчисліть хеш файлу!");
            return;
        }
        hash = window.fileHashData.hash;
        filepathInputId = "save-path-file";
        file_info = `File: ${window.fileHashData.filename}, path: ${window.fileHashData.filepath}`;
    }

    const filepath = document.getElementById(filepathInputId).value;
    if (!filepath) {
        alert("Введіть шлях до файлу, куди зберегти хеш!");
        return;
    }

    const res = await fetch("/save_hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash, filepath, input_str, file_info })
    });
    const result = await res.json();
    alert(result.message);
}

async function hashString() {
    const input = document.getElementById("input-string").value;
    const outputElement = document.getElementById("output-hash-string");
    const saveButton = document.getElementById("save-string-hash");

    if (!input) {
        outputElement.textContent = "Введіть рядок!";
        saveButton.style.display = "none";
        return;
    }

    const res = await fetch("/hash_string", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input })
    });
    const result = await res.json();

    outputElement.textContent = result.hash || result.error;
    saveButton.style.display = result.hash ? "inline" : "none";
}

async function hashFile() {
    const fileInput = document.getElementById("file-input");
    const outputElement = document.getElementById("output-hash-file");
    const saveButton = document.getElementById("save-file-hash");

    if (!fileInput.files.length) {
        outputElement.textContent = "Завантажте файл!";
        saveButton.style.display = "none";
        return;
    }

    outputElement.textContent = "Обчислення...";

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    const res = await fetch("/hash_file", {
        method: "POST",
        body: formData
    });
    const result = await res.json();

    if (result.error) {
        outputElement.textContent = result.error;
        saveButton.style.display = "none";
        return;
    }

    const filename = fileInput.files[0].name;

    outputElement.textContent =
        `Обчислено хеш для файлу:\n${filename}\n\nMD5 хеш:\n${result.hash}`;

    window.fileHashData = {
        hash: result.hash,
        filepath: result.filepath,
        filename: filename
    };

    saveButton.style.display = "inline";
}

async function processRC5(action) {
    const password = document.getElementById("rc5-password").value;
    const resultDiv = document.getElementById("rc5-result");
    let fileInput;
    let url;

    if (!password) {
        alert("Будь ласка, введіть пароль!");
        return;
    }

    if (action === 'encrypt') {
        fileInput = document.getElementById("encrypt-file-input");
        url = "/rc5_encrypt";
    } else {
        fileInput = document.getElementById("decrypt-file-input");
        url = "/rc5_decrypt";
    }

    if (!fileInput.files.length) {
        alert("Виберіть файл!");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("password", password);

    resultDiv.innerHTML = "Обробка...";

    try {
        const res = await fetch(url, {
            method: "POST",
            body: formData
        });
        const result = await res.json();

        if (result.error) {
            resultDiv.innerHTML = `<span style="color:red">${result.error}</span>`;
        } else {
            resultDiv.innerHTML = `
                <span style="color:green">${result.message}</span><br>
                Збережено як: <b>${result.filename}</b><br>
                <small>Шлях: ${result.path}</small>
            `;
        }
    } catch (err) {
        resultDiv.innerHTML = `<span style="color:red">Помилка з'єднання: ${err}</span>`;
    }
}

async function generateRSAKeys() {
    const res = await fetch("/rsa_gen_keys", { method: "POST" });
    const result = await res.json();

    if (result.error) {
        alert("Помилка: " + result.error);
    } else {
        document.getElementById("rsa-pub-key").value = result.public_key;
        document.getElementById("rsa-priv-key").value = result.private_key;

        document.getElementById("rsa-key-for-enc").value = result.public_key;
        document.getElementById("rsa-key-for-dec").value = result.private_key;
    }
}

async function processRSA(action) {
    const resultDiv = document.getElementById("rsa-result");
    let fileInput, keyInput, pathInput;

    if (action === 'encrypt') {
        fileInput = document.getElementById("rsa-enc-file");
        keyInput = document.getElementById("rsa-key-for-enc");
        pathInput = document.getElementById("rsa-path-enc");
    } else {
        fileInput = document.getElementById("rsa-dec-file");
        keyInput = document.getElementById("rsa-key-for-dec");
        pathInput = document.getElementById("rsa-path-dec");
    }

    if (!fileInput.files.length) {
        alert("Виберіть файл!");
        return;
    }
    if (!keyInput.value.trim()) {
        alert("Введіть необхідний ключ!");
        return;
    }
    if (!pathInput.value.trim()) {
        alert("Введіть шлях, куди зберегти файл!");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("key", keyInput.value);
    formData.append("action", action);
    formData.append("custom_path", pathInput.value.trim());

    resultDiv.innerHTML = "Обробка RSA...";

    try {
        const res = await fetch("/rsa_action", {
            method: "POST",
            body: formData
        });
        const result = await res.json();

        if (result.error) {
            resultDiv.innerHTML = `<span style="color:red">${result.error}</span>`;
        } else {
            resultDiv.innerHTML = `
                <span style="color:green">${result.message}</span><br>
                Файл збережено за шляхом: <b>${result.path}</b>
            `;
        }
    } catch (err) {
        resultDiv.innerHTML = `<span style="color:red">Помилка: ${err}</span>`;
    }
}

function downloadString(filename, elementId) {
    const text = document.getElementById(elementId).value;
    if(!text) {
        alert("Поле пусте!");
        return;
    }
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

async function generateDSSKeys() {
    const res = await fetch("/dss_gen_keys", { method: "POST" });
    const result = await res.json();
    if (result.error) {
        alert(result.error);
    } else {
        document.getElementById("dss-priv-key").value = result.private_key;
        document.getElementById("dss-pub-key").value = result.public_key;
    }
}

async function signDSS() {
    const source = document.getElementById("sign-source").value;
    const privKey = document.getElementById("dss-priv-key").value;

    if (!privKey) { alert("Потрібен приватний ключ!"); return; }

    const formData = new FormData();
    formData.append("source", source);
    formData.append("private_key", privKey);

    if (source === "text") {
        const text = document.getElementById("sign-input-text").value;
        if (!text) { alert("Введіть текст!"); return; }
        formData.append("text_input", text);
    } else {
        const fileInput = document.getElementById("sign-input-file");
        if (!fileInput.files.length) { alert("Виберіть файл!"); return; }
        formData.append("file", fileInput.files[0]);
    }

    try {
        const res = await fetch("/dss_sign", {
            method: "POST",
            body: formData
        });
        const result = await res.json();

        if (result.error) {
            alert("Помилка: " + result.error);
        } else {
            document.getElementById("dss-signature-out").value = result.signature;
        }
    } catch (e) {
        alert("Помилка з'єднання: " + e);
    }
}

async function verifyDSS() {
    const sourceType = document.getElementById("verify-source").value;
    const sigType = document.getElementById("sig-source-type").value;
    const pubKey = document.getElementById("dss-pub-key").value;
    const resultEl = document.getElementById("verify-result");

    if (!pubKey) { alert("Потрібен публічний ключ!"); return; }

    const formData = new FormData();
    formData.append("verify_type", sourceType);
    formData.append("public_key", pubKey);

    if (sourceType === "text") {
        formData.append("text_input", document.getElementById("verify-input-text").value);
    } else {
        const fileInput = document.getElementById("verify-input-file");
        if (!fileInput.files.length) { alert("Виберіть файл даних!"); return; }
        formData.append("file", fileInput.files[0]);
    }

    if (sigType === "manual") {
        const sig = document.getElementById("verify-sig-hex").value;
        if (!sig) { alert("Введіть підпис!"); return; }
        formData.append("signature", sig);
    } else {
        const sigFile = document.getElementById("verify-sig-file");
        if (!sigFile.files.length) { alert("Виберіть файл підпису!"); return; }
        formData.append("signature_file", sigFile.files[0]);
    }

    resultEl.innerText = "Перевірка...";
    resultEl.style.color = "blue";

    try {
        const res = await fetch("/dss_verify", {
            method: "POST",
            body: formData
        });
        const result = await res.json();

        resultEl.innerText = result.message;
        resultEl.style.color = result.valid ? "green" : "red";

    } catch (e) {
        resultEl.innerText = "Помилка: " + e;
        resultEl.style.color = "red";
    }
}

async function saveWithDialog() {
    const signature = document.getElementById("dss-signature-out").value;
    const statusText = document.getElementById("save-status-text");

    if (!signature) {
        alert("Спочатку згенеруйте підпис!");
        return;
    }

    statusText.textContent = "Відкриття вікна збереження...";
    statusText.style.color = "blue";

    try {
        const res = await fetch("/save_signature_local", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ signature: signature })
        });

        const result = await res.json();

        if (result.status === "success") {
            statusText.textContent = `Збережено: ${result.path}`;
            statusText.style.color = "green";
            alert(result.message);
        } else if (result.status === "cancel") {
            statusText.textContent = "Скасовано користувачем";
            statusText.style.color = "#666";
        } else {
            statusText.textContent = "Помилка збереження";
            statusText.style.color = "red";
            alert(result.error);
        }

    } catch (e) {
        statusText.textContent = "Помилка з'єднання";
        alert("Помилка: " + e);
    }
}