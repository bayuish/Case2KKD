from flask import Flask, request, jsonify, render_template_string
import threading, time, os, base64
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from paho.mqtt import client as mqtt_client

# =======================
#  3DES Utility Section
# =======================
def generate_key_iv():
    key = DES3.adjust_key_parity(get_random_bytes(24))  # 3DES needs 24-byte key
    iv = get_random_bytes(8)  # 64-bit IV
    return key, iv

def encrypt_3des_cfb(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_3des_cfb(ciphertext_b64, key, iv):
    ciphertext = base64.b64decode(ciphertext_b64.encode())
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

# =======================
#  MQTT + Flask Section
# =======================
broker = 'broker.emqx.io'
port = 1883
topic = "suhu/secure"
subscriber_client_id = 'subscriber-3des'
publisher_client_id = 'publisher-3des'

# Kunci tetap selama runtime
key, iv = generate_key_iv()

app = Flask(__name__)

# --- Subscriber MQTT ---
def start_subscriber():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("✅ Subscriber terhubung ke broker!")
            client.subscribe(topic)
            print(f"📡 Menunggu data terenkripsi dari topik '{topic}'...")
        else:
            print(f"❌ Gagal terhubung: {rc}")

    def on_message(client, userdata, msg):
        try:
            encrypted_data = msg.payload.decode()
            decrypted = decrypt_3des_cfb(encrypted_data, key, iv)
            print(f"🔓 Data didekripsi: {decrypted}°C ← dari topik '{msg.topic}'")
        except Exception as e:
            print(f"⚠️ Gagal mendekripsi: {e}")

    client = mqtt_client.Client(client_id=subscriber_client_id, protocol=mqtt_client.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker, port)
    client.loop_forever()

# --- HTML UI Form ---
HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kirim Suhu Aman (3DES)</title>
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
        <div class="status">Broker: mqtt://broker.emqx.io<br>Topik: suhu/secure</div>
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

    encrypted = encrypt_3des_cfb(suhu_str, key, iv)
    print(f"🔐 Suhu dienkripsi: {encrypted}")

    client = mqtt_client.Client(client_id=publisher_client_id, protocol=mqtt_client.MQTTv311)
    client.connect(broker, port)
    client.loop_start()
    time.sleep(1)
    result = client.publish(topic, encrypted)
    client.loop_stop()

    if result.rc == 0:
        return f"<h3>✅ Suhu terenkripsi {suhu_str}°C berhasil dikirim ke '{topic}'</h3><a href='/'>Kembali</a>"
    else:
        return "<h3>❌ Gagal mengirim suhu</h3>", 500

if __name__ == '__main__':
    print("🚀 Menjalankan Flask + MQTT Subscriber dengan 3DES...")

    # Langsung jalankan subscriber thread tanpa syarat env
    sub_thread = threading.Thread(target=start_subscriber)
    sub_thread.daemon = True
    sub_thread.start()

    app.run(debug=True, use_reloader=False)

