# Case2KKD


🔐 Perbandingan MQTT Menggunakan 3DES, Simeck, dan Skinny Cipher dalam Counter Feedback Mode (CFB)
Repositori ini berisi implementasi dan analisis perbandingan tiga algoritma kriptografi simetris — 3DES, Simeck, dan Skinny Cipher — yang digunakan untuk mengenkripsi payload dalam komunikasi MQTT (Message Queuing Telemetry Transport) dengan mode operasi Counter Feedback Mode (CFB).

📽️ **Link Demonstrasi**
Tonton demonstrasi proyek ini di YouTube:
👉 https://youtu.be/-9eF71eGiGk

📌 Deskripsi Proyek
Proyek ini mengeksplorasi performa dan keamanan dari tiga algoritma kriptografi ringan (lightweight) dan klasik dalam konteks komunikasi IoT yang menggunakan protokol MQTT. Implementasi dilakukan dengan mode operasi CFB, yang cocok untuk transmisi data streaming seperti pada MQTT.

Algoritma yang Digunakan:
3DES – Algoritma simetris klasik berbasis DES dengan 3 kali enkripsi.

Simeck – Algoritma ringan yang dirancang untuk perangkat embedded dan IoT.

Skinny – Cipher ringan dengan struktur SPN yang efisien untuk perangkat terbatas.

⚙️ Teknologi & Tools
Bahasa Pemrograman: Python / C/C++ (sesuaikan dengan repo Anda)

MQTT Broker: Mosquitto

MQTT Client: Paho MQTT / (sesuaikan jika menggunakan lainnya)

Library Cipher: PyCryptodome, custom implementation, atau lainnya

🧪 Fitur dan Eksperimen
Implementasi MQTT Publisher dan Subscriber dengan payload terenkripsi.

Mode operasi CFB untuk setiap algoritma.

Pengukuran performa:

Waktu enkripsi dan dekripsi

Ukuran pesan

Konsumsi memori (jika tersedia)

Analisis perbandingan efisiensi antara ketiga cipher.

🚀 Cara Menjalankan
Clone repositori ini

bash
Copy
Edit
git clone https://github.com/username/repo-mqtt-crypto.git
cd repo-mqtt-crypto
Instal dependensi

bash
Copy
Edit
pip install -r requirements.txt
Jalankan broker MQTT (jika lokal)

bash
Copy
Edit
mosquitto
Jalankan publisher dan subscriber

bash
Copy
Edit
python publisher.py
python subscriber.py
Pastikan konfigurasi algoritma dapat dipilih di parameter atau file konfigurasi.

📊 Hasil dan Analisis
File results/ berisi data eksperimen dan grafik perbandingan:

Kecepatan enkripsi dan dekripsi

Throughput pesan

Perbandingan ukuran pesan terenkripsi
