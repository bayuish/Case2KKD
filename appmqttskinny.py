from flask import Flask, request, jsonify, render_template_string
import threading, time, os, base64
from Crypto.Random import get_random_bytes
from paho.mqtt import client as mqtt_client

# =======================
#  Skinny Cipher Section
# =======================

class SkinnyCFB:
    def __init__(self, key: bytes, iv: bytes):
        self.rounds = 32
        self.block_size = 8  # 64-bit
        self.key = key
        self.iv = iv

    def skinny_encrypt(self, block: int, key: int) -> int:
        # Dummy round function (replace with real Skinny if needed)
        for _ in range(self.rounds):
            block = ((block << 1) ^ key) & 0xFFFFFFFFFFFFFFFF
        return block

    def encrypt(self, plaintext: str) -> str:
        ciphertext = b''
        prev = int.from_bytes(self.iv, 'big')
        key_int = int.from_bytes(self.key, 'big')
        plaintext_bytes = plaintext.encode()

        for byte in plaintext_bytes:
            keystream = self.skinny_encrypt(prev, key_int)
            ct_byte = byte ^ ((keystream >> 56) & 0xFF)
            ciphertext += bytes([ct_byte])
            prev = ((prev << 8) | ct_byte) & 0xFFFFFFFFFFFFFFFF

        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = b''
        prev = int.from_bytes(self.iv, 'big')
        key_int = int.from_bytes(self.key, 'big')

        for byte in ciphertext:
            keystream = self.skinny_encrypt(prev, key_int)
            pt_byte = byte ^ ((keystream >> 56) & 0xFF)
            plaintext += bytes([pt_byte])
            prev = ((prev << 8) | byte) & 0xFFFFFFFFFFFFFFFF

        return plaintext.decode()

def generate_skinny_key_iv():
    key = get_random_bytes(16)  # 128-bit key
    iv = get_random_bytes(8)    # 64-bit IV
    return key, iv

# =======================
#  Flask + MQTT Section
# =======================

broker = 'broker.emqx.io'
port = 1883
topic = "suhu/secure"
subscriber_client_id = 'subscriber-skinny'
publisher_client_id = 'publisher-skinny'

key, iv = generate_skinny_key_iv()
skinny = SkinnyCFB(key, iv)

app = Flask(__name__)

# --- Subscriber ---
def start_subscriber():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("✅ Subscriber terhubung ke broker!")
            client.subscribe(topic)
            print(f"📡 Menunggu data dari topik '{topic}'...")
        else:
            print(f"❌ Gagal koneksi, kode: {rc}")

    def on_message(client, userdata, msg):
        try:
            encrypted_data = msg.payload.decode()
            print(f"📥 Data terenkripsi diterima: {encrypted_data}")
            decrypted = skinny.decrypt(encrypted_data)
            print(f"🔓 Data didekripsi: {decrypted}°C")
        except Exception as e:
            print(f"⚠️ Gagal mendekripsi: {e}")

    client = mqtt_client.Client(client_id=subscriber_client_id, protocol=mqtt_client.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker, port)
    client.loop_forever()

# --- Form HTML ---
HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kirim Suhu Aman (skinny)</title>
    <style>
        body {
            background: #f2f6fc;
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .card {
            background: white;
            padding: 2rem 3rem;
            border-radius: 12px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            text-align: center;
            width: 350px;
        }
        h2 {
            color: #333;
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        input[type="number"] {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            margin-bottom: 1.5rem;
            border: 1px solid #ccc;
            border-radius: 8px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #45a049;
        }
        .status {
            margin-top: 1rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="card">
        <h2>Enkripsi Suhu (3DES)</h2>
        <form action="/send" method="post">
            <label for="suhu">Suhu (°C):</label>
            <input type="number" name="suhu" step="0.1" required>
            <button type="submit">Kirim</button>
        </form>
        <div class="status">Menggunakan protokol MQTT ke broker.emqx.io</div>
    </div>
</body>
</html>
"""



@app.route('/')
def index():
    return render_template_string(HTML_FORM)

# --- Publisher ---
@app.route('/send', methods=['POST'])
def send_suhu():
    suhu = request.form.get('suhu') or request.json.get('suhu')
    if not suhu:
        return jsonify({"error": "Masukkan suhu"}), 400

    try:
        suhu_str = str(float(suhu))
    except ValueError:
        return jsonify({"error": "Format suhu tidak valid"}), 400

    encrypted = skinny.encrypt(suhu_str)
    print(f"🔐 Suhu dienkripsi: {encrypted}")

    client = mqtt_client.Client(client_id=publisher_client_id, protocol=mqtt_client.MQTTv311)
    client.connect(broker, port)
    client.loop_start()
    time.sleep(1)
    result = client.publish(topic, encrypted)
    client.loop_stop()

    if result.rc == 0:
        return f"<h3>✅ Suhu terenkripsi {suhu_str}°C berhasil dikirim!</h3><a href='/'>Kembali</a>"
    else:
        return "<h3>❌ Gagal mengirim suhu</h3>", 500

# --- Jalankan Aplikasi ---
if __name__ == '__main__':
    print("🚀 Flask + MQTT Subscriber menggunakan Skinny siap dijalankan...")

    sub_thread = threading.Thread(target=start_subscriber)
    sub_thread.daemon = True
    sub_thread.start()

    app.run(debug=True, use_reloader=False)
