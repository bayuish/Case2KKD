from flask import Flask, request, jsonify, render_template_string
import threading, time, os, base64
from Crypto.Random import get_random_bytes
from paho.mqtt import client as mqtt_client

# =======================
#  Simeck Cipher Section
# =======================
class Simeck:
    def __init__(self, block_size, key_size, key):
        self.block_size = block_size
        self.key_size = key_size
        self.round_keys = self.key_schedule(key)

    def rol(self, x, r):
        return ((x << r) | (x >> (self.block_size // 2 - r))) & ((1 << (self.block_size // 2)) - 1)

    def simeck_round(self, l, r, k):
        tmp = r
        r = l ^ (self.rol(r, 5) & self.rol(r, 1)) ^ k
        l = tmp
        return l, r

    def key_schedule(self, master_key):
        k = [(master_key >> (16 * i)) & 0xFFFF for i in reversed(range(4))]
        z = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1,
             0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0]
        round_keys = []
        for i in range(32):
            round_keys.append(k[0])
            tmp = k[1]
            k[1], k[2], k[3] = k[2], k[3], k[0]
            k[0], tmp = self.simeck_round(k[0], tmp, z[i])
            k[1] ^= tmp
        return round_keys

    def encrypt(self, block):
        l = (block >> 32) & 0xFFFFFFFF
        r = block & 0xFFFFFFFF
        for k in self.round_keys:
            l, r = self.simeck_round(l, r, k)
        return (l << 32) | r

def generate_simeck_key_iv():
    key = int.from_bytes(get_random_bytes(16), 'big')  # 128-bit key
    iv = get_random_bytes(8)  # 64-bit IV
    return key, iv

def encrypt_simeck_cfb(plaintext: str, key: int, iv: bytes, block_size=64) -> str:
    simeck = Simeck(block_size, 128, key)
    ciphertext = b''
    prev = int.from_bytes(iv, 'big')
    plaintext_bytes = plaintext.encode()

    for byte in plaintext_bytes:
        keystream = simeck.encrypt(prev)
        keystream_byte = (keystream >> (block_size - 8)) & 0xFF
        ct_byte = byte ^ keystream_byte
        ciphertext += bytes([ct_byte])
        prev = ((prev << 8) | ct_byte) & ((1 << block_size) - 1)

    return base64.b64encode(ciphertext).decode()

def decrypt_simeck_cfb(ciphertext_b64: str, key: int, iv: bytes, block_size=64) -> str:
    simeck = Simeck(block_size, 128, key)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = b''
    prev = int.from_bytes(iv, 'big')

    for byte in ciphertext:
        keystream = simeck.encrypt(prev)
        keystream_byte = (keystream >> (block_size - 8)) & 0xFF
        pt_byte = byte ^ keystream_byte
        plaintext += bytes([pt_byte])
        prev = ((prev << 8) | byte) & ((1 << block_size) - 1)

    return plaintext.decode()

# =======================
#  Flask + MQTT App
# =======================
broker = 'broker.emqx.io'
port = 1883
topic = "suhu/secure"
subscriber_client_id = 'subscriber-simeck'
publisher_client_id = 'publisher-simeck'

# Gunakan 1 key/iv tetap (satu sesi)
key, iv = generate_simeck_key_iv()

app = Flask(__name__)

# --- Subscriber MQTT ---
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
            decrypted = decrypt_simeck_cfb(encrypted_data, key, iv)
            print(f"🔓 Data didekripsi: {decrypted}°C")
        except Exception as e:
            print(f"⚠️ Gagal mendekripsi: {e}")

    client = mqtt_client.Client(client_id=subscriber_client_id, protocol=mqtt_client.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker, port)
    client.loop_forever()

# --- Halaman Form ---
HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kirim Suhu Aman (Simeck)</title>
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
        suhu_str = str(float(suhu))  # validasi float
    except ValueError:
        return jsonify({"error": "Format suhu tidak valid"}), 400

    encrypted = encrypt_simeck_cfb(suhu_str, key, iv)
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

# --- Run Flask dan Subscriber ---
if __name__ == '__main__':
    print("🚀 Flask + MQTT Subscriber menggunakan Simeck siap dijalankan...")

    sub_thread = threading.Thread(target=start_subscriber)
    sub_thread.daemon = True
    sub_thread.start()

    app.run(debug=True, use_reloader=False)
