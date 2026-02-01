import pytest
import io
import os
import shutil
import hashlib
from app import app
from backend.generator import lcg_generate, find_period
from backend.cesaro_test import cesaro_test
from backend.md5_hash import hash_string, hash_file, verify_file
from backend.rc5 import RC5, pad_data, unpad_data, encrypt_file_rc5, decrypt_file_rc5
from backend.rsa import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa

def test_lcg_generate():
    seq = lcg_generate(a=5, c=3, m=16, x0=1, n=5)
    assert len(seq) == 5
    assert seq[0] == 8
    assert isinstance(seq, list)


def test_find_period():
    p = find_period(a=1,c=1,m=4,x0=0)
    assert p == 4


def test_cesaro_logic():
    pi_est, prob = cesaro_test(100, a=1664525, c=1013904223, m=2 ** 32, x0=1)
    assert isinstance(pi_est, float)
    assert 0 <= prob <= 1

    with pytest.raises(ValueError):
        cesaro_test(0, 1, 1, 1, 1)


def test_md5_string():
    input_str = "hello world"
    expected = hashlib.md5(input_str.encode()).hexdigest().upper()
    assert hash_string(input_str) == expected


def test_md5_file(tmp_path):
    d = tmp_path / "subdir"
    d.mkdir()
    p = d / "test_hash.txt"
    p.write_text("content")

    expected = hashlib.md5(b"content").hexdigest().upper()
    assert hash_file(str(p)) == expected
    assert verify_file(str(p), expected) is True
    assert verify_file(str(p), "WRONGHASH") is False


def test_rc5_padding():
    data = b"123"
    padded = pad_data(data)
    assert len(padded) == 16
    assert unpad_data(padded) == data

    assert unpad_data(b"") == b""

    bad_data = b"some_data" + b"\xff"
    with pytest.raises(ValueError):
        unpad_data(bad_data)

def test_rc5_class():
    key = b"1234567890123456"
    cipher = RC5(key)
    block = b"\x00" * 16
    enc = cipher.encrypt_block(block)
    dec = cipher.decrypt_block(enc)
    assert dec == block


def test_rc5_file_encrypt_decrypt(tmp_path):
    d = tmp_path / "rc5_test"
    d.mkdir()
    input_file = d / "plain.txt"
    enc_file = d / "enc.bin"
    dec_file = d / "dec.txt"

    original_text = b"This is a secret message that is longer than 16 bytes."
    input_file.write_bytes(original_text)

    password = "secure_password"

    encrypt_file_rc5(str(input_file), str(enc_file), password)
    assert enc_file.exists()
    assert enc_file.read_bytes() != original_text

    decrypt_file_rc5(str(enc_file), str(dec_file), password)
    assert dec_file.read_bytes() == original_text


def test_rsa_keygen_logic():
    priv_pem, pub_pem = generate_rsa_keys(key_size=1024)

    assert isinstance(priv_pem, bytes)
    assert isinstance(pub_pem, bytes)
    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem


def test_rsa_encrypt_decrypt_logic(tmp_path):
    d = tmp_path / "rsa_test"
    d.mkdir()
    input_file = d / "plain.txt"
    enc_file = d / "encrypted.bin"
    dec_file = d / "decrypted.txt"

    original_data = b"A" * 300
    input_file.write_bytes(original_data)

    priv_pem, pub_pem = generate_rsa_keys(key_size=2048)

    encrypt_file_rsa(str(input_file), str(enc_file), pub_pem)

    assert enc_file.exists()
    assert enc_file.stat().st_size > 0
    assert enc_file.read_bytes() != original_data

    decrypt_file_rsa(str(enc_file), str(dec_file), priv_pem)

    assert dec_file.exists()
    assert dec_file.read_bytes() == original_data






@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = 'test_output'
    os.makedirs('test_output', exist_ok=True)

    with app.test_client() as client:
        yield client

    if os.path.exists('test_output'):
        shutil.rmtree('test_output')
    if os.path.exists('output'):
        shutil.rmtree('output')


def test_home_and_pages(client):
    assert client.get('/').status_code == 200
    assert client.get('/lab1').status_code == 200
    assert client.get('/lab2').status_code == 200
    assert client.get('/lab3').status_code == 200
    assert client.get('/lab4').status_code == 200


def test_route_generate(client):
    payload = {"a": 5, "c": 3, "m": 16, "x0": 1, "n": 5}
    response = client.post('/generate', json=payload)
    data = response.get_json()
    assert response.status_code == 200
    assert len(data['sequence']) == 5


def test_route_period(client):
    payload = {"a": 1, "c": 1, "m": 4, "x0": 0}
    response = client.post('/period', json=payload)
    assert response.get_json()['period'] == 4


def test_route_cesaro(client):
    payload = {"a": 1664525, "c": 1013904223, "m": 2 ** 32, "x0": 1, "samples": 50}
    response = client.post('/cesaro', json=payload)
    data = response.get_json()
    assert "pi_est" in data


def test_route_hash_string(client):
    response = client.post('/hash_string', json={"input": "test"})
    assert "hash" in response.get_json()


def test_route_hash_file(client):
    data = {
        'file': (io.BytesIO(b"file content"), 'test.txt')
    }
    response = client.post('/hash_file', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.get_json()['hash'] is not None


def test_route_verify_file(client):
    file_content = b"content"
    correct_hash = hashlib.md5(file_content).hexdigest().upper()

    data = {'file': (io.BytesIO(file_content), 'verify.txt')}
    client.post('/hash_file', data=data, content_type='multipart/form-data')

    payload = {
        "filepath": os.path.join("output", "verify.txt"),
        "expected_hash": correct_hash
    }
    response = client.post('/verify_file', json=payload)
    assert response.get_json()['is_valid'] is True


def test_route_rc5_encrypt_decrypt(client):
    file_content = b"secret data"
    data = {
        'file': (io.BytesIO(file_content), 'secret.txt'),
        'password': 'pass'
    }
    resp_enc = client.post('/rc5_encrypt', data=data, content_type='multipart/form-data')
    assert resp_enc.status_code == 200
    enc_path = resp_enc.get_json()['path']

    with open(enc_path, 'rb') as f:
        encrypted_content = f.read()

    data_dec = {
        'file': (io.BytesIO(encrypted_content), 'enc_secret.txt'),
        'password': 'pass'
    }
    resp_dec = client.post('/rc5_decrypt', data=data_dec, content_type='multipart/form-data')
    assert resp_dec.status_code == 200
    assert resp_dec.get_json()['message'] == "Файл успішно розшифровано!"


def test_route_rc5_errors(client):
    data = {'file': (io.BytesIO(b"data"), 'test.txt')}
    resp = client.post('/rc5_encrypt', data=data, content_type='multipart/form-data')
    assert "error" in resp.get_json()


def test_save_sequence(client):
    filepath = os.path.join("test_output", "seq.txt")
    payload = {
        "sequence": [1, 2, 3],
        "filepath": filepath,
        "paramsStr": "a=1"
    }
    resp = client.post('/save_sequence', json=payload)
    assert resp.status_code == 200
    assert os.path.exists(filepath)


def test_save_hash(client):
    filepath = os.path.join("test_output", "hash.txt")
    payload = {
        "hash": "ABCD",
        "filepath": filepath,
        "input_str": "test"
    }
    resp = client.post('/save_hash', json=payload)
    assert resp.status_code == 200
    assert os.path.exists(filepath)


def test_route_rsa_gen_keys(client):
    response = client.post('/rsa_gen_keys')
    assert response.status_code == 200
    data = response.get_json()

    assert "private_key" in data
    assert "public_key" in data
    assert "BEGIN PUBLIC KEY" in data["public_key"]


def test_route_rsa_full_flow(client):
    resp_keys = client.post('/rsa_gen_keys')
    keys = resp_keys.get_json()
    pub_key = keys['public_key']
    priv_key = keys['private_key']

    original_content = b"Secret RSA Message via Flask"
    filename = "secret_rsa.txt"

    enc_path = os.path.abspath(os.path.join("test_output", "rsa_result_enc.bin"))
    dec_path = os.path.abspath(os.path.join("test_output", "rsa_result_dec.txt"))

    data_enc = {
        'file': (io.BytesIO(original_content), filename),
        'key': pub_key,
        'action': 'encrypt',
        'custom_path': enc_path
    }

    resp_enc = client.post('/rsa_action', data=data_enc, content_type='multipart/form-data')
    assert resp_enc.status_code == 200
    json_enc = resp_enc.get_json()

    assert "Файл зашифровано" in json_enc['message']
    assert os.path.exists(enc_path)

    with open(enc_path, "rb") as f:
        encrypted_content = f.read()

    data_dec = {
        'file': (io.BytesIO(encrypted_content), "encrypted_file.bin"),
        'key': priv_key,
        'action': 'decrypt',
        'custom_path': dec_path
    }

    resp_dec = client.post('/rsa_action', data=data_dec, content_type='multipart/form-data')
    assert resp_dec.status_code == 200

    assert os.path.exists(dec_path)
    with open(dec_path, "rb") as f:
        decrypted_content = f.read()

    assert decrypted_content == original_content


def test_route_rsa_errors(client):

    resp = client.post('/rsa_action', data={
        'key': 'some_key',
        'action': 'encrypt',
        'custom_path': 'some/path'
    })
    assert "Файл не завантажено" in resp.get_json()['error']

    resp = client.post('/rsa_action', data={
        'file': (io.BytesIO(b"data"), 'test.txt'),
        'action': 'encrypt',
        'custom_path': 'some/path'
    }, content_type='multipart/form-data')
    assert "Ключ не надано" in resp.get_json()['error']

    resp = client.post('/rsa_action', data={
        'file': (io.BytesIO(b"data"), 'test.txt'),
        'key': 'some_key',
        'action': 'encrypt'
    }, content_type='multipart/form-data')
    assert "Шлях збереження не вказано" in resp.get_json()['error']

    enc_path = os.path.join("test_output", "fail.bin")
    resp = client.post('/rsa_action', data={
        'file': (io.BytesIO(b"data"), 'test.txt'),
        'key': 'BAD_KEY_STRING',
        'action': 'encrypt',
        'custom_path': enc_path
    }, content_type='multipart/form-data')

    assert "error" in resp.get_json()

