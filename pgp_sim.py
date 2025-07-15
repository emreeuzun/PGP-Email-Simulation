import os
import json
import base64
import zlib
import socket
import threading
import time
import signal
import sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets


class PGPChatSystem:
    def __init__(self, peer_name, host='localhost', port=9999):
        self.peer_name = peer_name
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.peer_public_keys = {}
        self.server_socket = None
        self.is_server_running = False
        self.chat_active = False
        self.current_chat_partner = None
        self.keys_directory = os.path.expanduser("~/.pgp_chat_keys")
        self.received_files_directory = os.path.expanduser("~/.pgp_chat_received")

        # Dizinleri oluştur
        self._create_keys_directory()
        self._create_received_files_directory()

        # Signal handler'ları ayarla (Linux/Unix için)
        self._setup_signal_handlers()

    def _create_keys_directory(self):
        try:
            if not os.path.exists(self.keys_directory):
                os.makedirs(self.keys_directory, mode=0o700)  # Sadece kullanıcı erişimi
                print(f"📁 Anahtar dizini oluşturuldu: {self.keys_directory}")
        except Exception as e:
            print(f"⚠️ Anahtar dizini oluşturulamadı: {e}")
            # Fallback olarak current directory kullan
            self.keys_directory = os.getcwd()

    def _create_received_files_directory(self):
        try:
            if not os.path.exists(self.received_files_directory):
                os.makedirs(self.received_files_directory, mode=0o755)
                print(f"📁 Alınan dosyalar dizini oluşturuldu: {self.received_files_directory}")
        except Exception as e:
            print(f"⚠️ Alınan dosyalar dizini oluşturulamadı: {e}")
            # Fallback olarak current directory kullan
            self.received_files_directory = os.getcwd()

    def _setup_signal_handlers(self):
        if os.name != 'nt':  # Windows değilse
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"\n🛑 Signal {signum} alındı, sistem kapatılıyor...")
        self.chat_active = False
        self.stop_server()
        sys.exit(0)

    def generate_key_pair(self):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            print(f"🔑 Anahtar çifti oluşturuldu: {self.peer_name}")
        except Exception as e:
            print(f"❌ Anahtar oluşturma hatası: {e}")
            raise

    def export_public_key(self):
        if not self.public_key:
            raise ValueError("Önce anahtar çifti oluşturun!")
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        except Exception as e:
            print(f"❌ Public key export hatası: {e}")
            raise

    def import_peer_public_key(self, peer_name, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            self.peer_public_keys[peer_name] = public_key
            print(f"🔐 {peer_name} adlı kişinin public key'i alındı")
            return True
        except Exception as e:
            print(f"❌ Public key import hatası: {e}")
            return False

    def create_key_exchange_message(self):
        return {
            'type': 'KEY_EXCHANGE',
            'sender': self.peer_name,
            'public_key': self.export_public_key(),
            'timestamp': time.time()
        }

    def encrypt_file(self, file_path, recipient_name):
        if recipient_name not in self.peer_public_keys:
            raise ValueError(f"{recipient_name} adlı kişinin public key'i bulunamadı!")

        if not os.path.exists(file_path):
            raise ValueError(f"Dosya bulunamadı: {file_path}")

        try:
            recipient_public_key = self.peer_public_keys[recipient_name]
            
            # Dosyayı oku
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Dosya bilgilerini hazırla
            file_name = os.path.basename(file_path)
            file_size = len(file_data)
            
            print(f"📄 Dosya şifreleniyor: {file_name} ({file_size} bytes)")

            # Dosya hash'i oluştur (bütünlük kontrolü için)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(file_data)
            file_hash = digest.finalize()

            # Dijital imza oluştur
            signature = self.private_key.sign(
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Dosya verisini ve imzayı birleştir
            signed_data = file_data + b"||SIGNATURE||" + signature + b"||HASH||" + file_hash
            compressed_data = zlib.compress(signed_data, level=9)

            # Büyük dosyalar için chunk'lara böl (maks 64KB chunks)
            chunk_size = 65536  # 64KB
            chunks = []
            
            for i in range(0, len(compressed_data), chunk_size):
                chunk = compressed_data[i:i + chunk_size]
                
                # Her chunk'ı AES ile şifrele
                session_key = secrets.token_bytes(32)
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padded_chunk = self._pad_data(chunk)
                encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()

                # Session key'i RSA ile şifrele
                encrypted_session_key = recipient_public_key.encrypt(
                    session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                chunk_data = {
                    'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                    'iv': base64.b64encode(iv).decode('utf-8'),
                    'encrypted_data': base64.b64encode(encrypted_chunk).decode('utf-8')
                }
                chunks.append(chunk_data)

            encrypted_file_package = {
                'type': 'ENCRYPTED_FILE',
                'file_name': file_name,
                'file_size': file_size,
                'original_size': len(file_data),
                'compressed_size': len(compressed_data),
                'chunk_count': len(chunks),
                'chunks': chunks,
                'sender': self.peer_name,
                'recipient': recipient_name,
                'timestamp': time.time()
            }

            print(f"✅ Dosya şifrelendi: {len(chunks)} chunk oluşturuldu")
            return encrypted_file_package

        except Exception as e:
            print(f"❌ Dosya şifreleme hatası: {e}")
            raise

    def decrypt_file(self, encrypted_file_package):
        if not self.private_key:
            raise ValueError("Private key bulunamadı!")

        sender_name = encrypted_file_package['sender']
        if sender_name not in self.peer_public_keys:
            raise ValueError(f"{sender_name} adlı gönderenin public key'i bulunamadı!")

        try:
            sender_public_key = self.peer_public_keys[sender_name]
            file_name = encrypted_file_package['file_name']
            chunks = encrypted_file_package['chunks']
            
            print(f"📄 Dosya çözülüyor: {file_name} ({len(chunks)} chunk)")

            # Chunk'ları çöz ve birleştir
            decrypted_data = b""
            
            for i, chunk_data in enumerate(chunks):
                print(f"🔓 Chunk {i+1}/{len(chunks)} çözülüyor...", end='\r')
                
                # Base64 decode
                encrypted_session_key = base64.b64decode(chunk_data['encrypted_session_key'])
                iv = base64.b64decode(chunk_data['iv'])
                encrypted_chunk = base64.b64decode(chunk_data['encrypted_data'])

                # Session key'i çöz
                session_key = self.private_key.decrypt(
                    encrypted_session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # AES ile çöz
                cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
                chunk = self._unpad_data(padded_chunk)
                decrypted_data += chunk

            print()
            
            # Sıkıştırmayı çöz
            decompressed_data = zlib.decompress(decrypted_data)

            # İmzayı ve hash'i ayır
            parts = decompressed_data.split(b"||SIGNATURE||")
            if len(parts) != 2:
                raise ValueError("Dosya formatı hatalı!")

            file_data = parts[0]
            signature_and_hash = parts[1]

            hash_parts = signature_and_hash.split(b"||HASH||")
            if len(hash_parts) != 2:
                raise ValueError("Hash formatı hatalı!")

            signature = hash_parts[0]
            received_hash = hash_parts[1]

            # Dosya bütünlüğünü kontrol et
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(file_data)
            calculated_hash = digest.finalize()

            if calculated_hash != received_hash:
                raise ValueError("Dosya bütünlük kontrolü başarısız!")

            # İmzayı doğrula
            try:
                sender_public_key.verify(
                    signature,
                    received_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            except:
                signature_valid = False

            return file_data, signature_valid

        except Exception as e:
            print(f"❌ Dosya çözme hatası: {e}")
            raise

    def encrypt_message(self, message, recipient_name):
        if recipient_name not in self.peer_public_keys:
            raise ValueError(f"{recipient_name} adlı kişinin public key'i bulunamadı!")

        try:
            recipient_public_key = self.peer_public_keys[recipient_name]
            original_message = message.encode('utf-8')

            # Dijital imza oluştur
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(original_message)
            message_hash = digest.finalize()

            signature = self.private_key.sign(
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Mesaj ve imzayı birleştir
            signed_message = original_message + b"||SIGNATURE||" + signature
            compressed_data = zlib.compress(signed_message)

            # AES ile şifrele
            session_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = self._pad_data(compressed_data)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Session key'i RSA ile şifrele
            encrypted_session_key = recipient_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_package = {
                'type': 'ENCRYPTED_MESSAGE',
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                'sender': self.peer_name,
                'recipient': recipient_name,
                'timestamp': time.time()
            }
            return encrypted_package
        except Exception as e:
            print(f"❌ Şifreleme hatası: {e}")
            raise

    def decrypt_message(self, encrypted_package):
        if not self.private_key:
            raise ValueError("Private key bulunamadı!")

        sender_name = encrypted_package['sender']
        if sender_name not in self.peer_public_keys:
            raise ValueError(f"{sender_name} adlı gönderenin public key'i bulunamadı!")

        try:
            sender_public_key = self.peer_public_keys[sender_name]

            # Base64 decode
            encrypted_session_key = base64.b64decode(encrypted_package['encrypted_session_key'])
            iv = base64.b64decode(encrypted_package['iv'])
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])

            # Session key'i çöz
            session_key = self.private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # AES ile çöz
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            compressed_data = self._unpad_data(padded_data)
            signed_message = zlib.decompress(compressed_data)

            # İmzayı ayır
            parts = signed_message.split(b"||SIGNATURE||")
            if len(parts) != 2:
                raise ValueError("Mesaj formatı hatalı!")

            original_message, signature = parts

            # İmzayı doğrula
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(original_message)
            message_hash = digest.finalize()

            try:
                sender_public_key.verify(
                    signature,
                    message_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            except:
                signature_valid = False

            return original_message.decode('utf-8'), signature_valid
        except Exception as e:
            print(f"❌ Çözme hatası: {e}")
            raise

    def _pad_data(self, data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    def _unpad_data(self, padded_data):
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            self.is_server_running = True

            print(f"🟢 Sunucu başlatıldı: {self.host}:{self.port}")
            print("💬 Mesaj ve dosya almaya hazır... (Ctrl+C ile çıkış)")
            print("-" * 50)

            while self.is_server_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_server_running:
                        print(f"❌ Sunucu hatası: {e}")
                    break

        except KeyboardInterrupt:
            print("\n🛑 Ctrl+C algılandı, sunucu durduruluyor.")
        except Exception as e:
            print(f"❌ Sunucu başlatma hatası: {e}")
        finally:
            self.stop_server()

    def _handle_client(self, client_socket, addr):
        """İstemci bağlantısını yönetir"""
        try:
            # Mesaj boyutunu al
            size_data = client_socket.recv(8)
            if not size_data:
                return

            message_size = int.from_bytes(size_data, 'big')
            message_data = b""

            # Tam mesajı al
            while len(message_data) < message_size:
                chunk = client_socket.recv(min(4096, message_size - len(message_data)))
                if not chunk:
                    break
                message_data += chunk

            if len(message_data) != message_size:
                print(f"⚠️ Mesaj boyutu uyuşmazlığı: {len(message_data)} != {message_size}")
                return

            package = json.loads(message_data.decode('utf-8'))

            if package['type'] == 'KEY_EXCHANGE':
                # Public key değişimi
                sender_name = package['sender']
                public_key_pem = package['public_key']

                if self.import_peer_public_key(sender_name, public_key_pem):
                    print(f"🔗 {sender_name} ile bağlantı kuruldu")

                    # Kendi public key'imizi gönder
                    response = self.create_key_exchange_message()
                    response_data = json.dumps(response).encode('utf-8')
                    client_socket.send(len(response_data).to_bytes(8, 'big'))
                    client_socket.send(response_data)

                    self.current_chat_partner = sender_name
                    self.chat_active = True
                else:
                    client_socket.send(b"KEY_EXCHANGE_FAILED")

            elif package['type'] == 'ENCRYPTED_MESSAGE':
                # Şifreli mesaj
                sender_name = package['sender']
                timestamp = datetime.fromtimestamp(package['timestamp'])

                try:
                    decrypted_message, signature_valid = self.decrypt_message(package)

                    # Mesajı göster
                    time_str = timestamp.strftime("%H:%M:%S")
                    signature_icon = "✅" if signature_valid else "⚠️"
                    print(f"\n[{time_str}] {sender_name} {signature_icon}: {decrypted_message}")

                    # Exit kontrolü
                    if decrypted_message.strip().lower() == "exit":
                        print(f"🔚 {sender_name} sohbetten ayrıldı.")
                        self.chat_active = False
                        self.stop_server()

                    client_socket.send(b"MESSAGE_RECEIVED_OK")

                except Exception as e:
                    print(f"❌ Mesaj çözme hatası: {e}")
                    client_socket.send(b"MESSAGE_DECRYPT_ERROR")

            elif package['type'] == 'ENCRYPTED_FILE':
                # Şifreli dosya
                sender_name = package['sender']
                file_name = package['file_name']
                timestamp = datetime.fromtimestamp(package['timestamp'])

                try:
                    print(f"\n📨 {sender_name} bir dosya gönderiyor: {file_name}")
                    
                    file_data, signature_valid = self.decrypt_file(package)
                    
                    # Dosyayı kaydet
                    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_filename = f"{timestamp_str}_{sender_name}_{file_name}"
                    file_path = os.path.join(self.received_files_directory, safe_filename)
                    
                    with open(file_path, 'wb') as f:
                        f.write(file_data)

                    time_str = timestamp.strftime("%H:%M:%S")
                    signature_icon = "✅" if signature_valid else "⚠️"
                    print(f"[{time_str}] {sender_name} {signature_icon} dosya alındı: {file_name}")
                    print(f"📁 Kaydedildi: {file_path}")
                    print(f"📊 Boyut: {len(file_data)} bytes")

                    client_socket.send(b"FILE_RECEIVED_OK")

                except Exception as e:
                    print(f"❌ Dosya alma hatası: {e}")
                    client_socket.send(b"FILE_DECRYPT_ERROR")

        except Exception as e:
            print(f"❌ İstemci işleme hatası: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def connect_and_chat(self, recipient_name, recipient_host, recipient_port=None):
        if recipient_port is None:
            recipient_port = self.port

        try:
            # İlk olarak key exchange yap
            print(f"🔗 {recipient_name} ile bağlantı kuruluyor...")

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((recipient_host, recipient_port))

            # Public key gönder
            key_exchange_msg = self.create_key_exchange_message()
            json_data = json.dumps(key_exchange_msg).encode('utf-8')
            client_socket.send(len(json_data).to_bytes(8, 'big'))
            client_socket.send(json_data)

            # Karşı tarafın public key'ini al
            size_data = client_socket.recv(8)
            if size_data:
                response_size = int.from_bytes(size_data, 'big')
                response_data = b""
                while len(response_data) < response_size:
                    chunk = client_socket.recv(min(4096, response_size - len(response_data)))
                    if not chunk:
                        break
                    response_data += chunk

                if len(response_data) == response_size:
                    response = json.loads(response_data.decode('utf-8'))
                    if response['type'] == 'KEY_EXCHANGE':
                        if self.import_peer_public_key(response['sender'], response['public_key']):
                            print(f"✅ {recipient_name} ile güvenli bağlantı kuruldu!")
                            self.current_chat_partner = recipient_name
                            self.chat_active = True

            client_socket.close()

            # Sohbet döngüsünü başlat
            if self.chat_active:
                self._start_chat_loop(recipient_name, recipient_host, recipient_port)
            else:
                print("❌ Güvenli bağlantı kurulamadı!")

        except Exception as e:
            print(f"❌ Bağlantı kurulamadı: {e}")

    def _start_chat_loop(self, recipient_name, recipient_host, recipient_port):
        print(f"\n💬 {recipient_name} ile sohbet başladı!")
        print("📝 Komutlar:")
        print("  • Mesaj yazmak için: mesajınızı yazın")
        print("  • Dosya göndermek için: /file <dosya_yolu>")
        print("  • Çıkmak için: exit")
        print("-" * 50)

        while self.chat_active:
            try:
                user_input = input(f"[Sen]: ").strip()

                if not user_input:
                    continue

                if user_input.lower() == "exit":
                    print("🔚 Sohbetten çıkılıyor...")
                    self.chat_active = False
                    break

                # Dosya gönderme komutu kontrolü
                if user_input.startswith('/file '):
                    file_path = user_input[6:].strip()
                    if file_path:
                        self.send_file(file_path, recipient_name, recipient_host, recipient_port)
                    else:
                        print("❌ Dosya yolu belirtilmedi! Kullanım: /file <dosya_yolu>")
                else:
                    # Normal mesaj gönder
                    self.send_message(user_input, recipient_name, recipient_host, recipient_port)

            except KeyboardInterrupt:
                print("\n🔚 Sohbet sonlandırılıyor...")
                self.chat_active = False
                break
            except EOFError:
                print("\n🔚 EOF algılandı, sohbet sonlandırılıyor...")
                self.chat_active = False
                break
            except Exception as e:
                print(f"❌ Girdi hatası: {e}")

    def send_file(self, file_path, recipient_name, recipient_host, recipient_port=None):
        if recipient_port is None:
            recipient_port = self.port

        if not os.path.exists(file_path):
            print(f"❌ Dosya bulunamadı: {file_path}")
            return

        try:
            print(f"📤 Dosya gönderiliyor: {os.path.basename(file_path)}")
            
            encrypted_package = self.encrypt_file(file_path, recipient_name)
            json_data = json.dumps(encrypted_package).encode('utf-8')

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(30)  # Dosyalar için daha uzun timeout
            client_socket.connect((recipient_host, recipient_port))

            client_socket.send(len(json_data).to_bytes(8, 'big'))
            client_socket.send(json_data)

            response = client_socket.recv(1024)
            if response == b"FILE_RECEIVED_OK":
                time_str = datetime.now().strftime("%H:%M:%S")
                print(f"[{time_str}] ✅ Dosya başarıyla gönderildi")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️ Dosya gönderim durumu bilinmiyor")

            client_socket.close()

        except Exception as e:
            print(f"❌ Dosya gönderilemedi: {e}")

    def send_message(self, message, recipient_name, recipient_host, recipient_port=None):
        if recipient_port is None:
            recipient_port = self.port

        try:
            encrypted_package = self.encrypt_message(message, recipient_name)
            json_data = json.dumps(encrypted_package).encode('utf-8')

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((recipient_host, recipient_port))

            client_socket.send(len(json_data).to_bytes(8, 'big'))
            client_socket.send(json_data)

            response = client_socket.recv(1024)
            if response == b"MESSAGE_RECEIVED_OK":
                time_str = datetime.now().strftime("%H:%M:%S")
                print(f"[{time_str}] ✅ Mesaj iletildi")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️ Mesaj durumu bilinmiyor")

            client_socket.close()

        except Exception as e:
            print(f"❌ Mesaj gönderilemedi: {e}")

    def stop_server(self):
        self.is_server_running = False
        self.chat_active = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            print("🔴 Sunucu durduruldu")

    def load_or_create_keys(self):
        priv_file = os.path.join(self.keys_directory, f"{self.peer_name}_private_key.pem")
        pub_file = os.path.join(self.keys_directory, f"{self.peer_name}_public_key.pem")

        if os.path.exists(priv_file) and os.path.exists(pub_file):
            try:
                with open(priv_file, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                with open(pub_file, 'r') as f:
                    public_key_pem = f.read()
                    self.public_key = serialization.load_pem_public_key(
                        public_key_pem.encode('utf-8'), backend=default_backend()
                    )
                print(f"🔑 Mevcut anahtarlar yüklendi: {self.peer_name}")
            except Exception as e:
                print(f"⚠️ Anahtar yükleme hatası: {e}")
                print("🔄 Yeni anahtarlar oluşturuluyor...")
                self.generate_key_pair()
                self._save_keys()
        else:
            self.generate_key_pair()
            self._save_keys()

    def _save_keys(self):
        priv_file = os.path.join(self.keys_directory, f"{self.peer_name}_private_key.pem")
        pub_file = os.path.join(self.keys_directory, f"{self.peer_name}_public_key.pem")

        try:
            # Private key'i güvenli izinlerle kaydet
            with open(priv_file, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Linux/Unix'te private key dosyasının izinlerini ayarla
            if os.name != 'nt':
                os.chmod(priv_file, 0o600)  # Sadece owner okuma/yazma

            with open(pub_file, 'w') as f:
                f.write(self.export_public_key())

            print(f"🔑 Anahtarlar kaydedildi: {self.keys_directory}")

        except Exception as e:
            print(f"❌ Anahtar kaydetme hatası: {e}")

    def get_system_info(self):
        print(f"🖥️  İşletim Sistemi: {os.name}")
        print(f"📁 Anahtar Dizini: {self.keys_directory}")
        print(f"📁 Alınan Dosyalar Dizini: {self.received_files_directory}")
        print(f"🌐 Sunucu Adresi: {self.host}:{self.port}")
        print(f"👤 Peer Adı: {self.peer_name}")

    def file_transfer_mode(self, recipient_name, recipient_host, recipient_port=None):
        if recipient_port is None:
            recipient_port = self.port

        try:
            # İlk olarak key exchange yap
            print(f"🔗 {recipient_name} ile bağlantı kuruluyor...")

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((recipient_host, recipient_port))

            # Public key gönder
            key_exchange_msg = self.create_key_exchange_message()
            json_data = json.dumps(key_exchange_msg).encode('utf-8')
            client_socket.send(len(json_data).to_bytes(8, 'big'))
            client_socket.send(json_data)

            # Karşı tarafın public key'ini al
            size_data = client_socket.recv(8)
            if size_data:
                response_size = int.from_bytes(size_data, 'big')
                response_data = b""
                while len(response_data) < response_size:
                    chunk = client_socket.recv(min(4096, response_size - len(response_data)))
                    if not chunk:
                        break
                    response_data += chunk

                if len(response_data) == response_size:
                    response = json.loads(response_data.decode('utf-8'))
                    if response['type'] == 'KEY_EXCHANGE':
                        if self.import_peer_public_key(response['sender'], response['public_key']):
                            print(f"✅ {recipient_name} ile güvenli bağlantı kuruldu!")
                            self.current_chat_partner = recipient_name
                            self.chat_active = True

            client_socket.close()

            # Dosya transfer döngüsünü başlat
            if self.chat_active:
                self._start_file_transfer_loop(recipient_name, recipient_host, recipient_port)
            else:
                print("❌ Güvenli bağlantı kurulamadı!")

        except Exception as e:
            print(f"❌ Bağlantı kurulamadı: {e}")

    def _start_file_transfer_loop(self, recipient_name, recipient_host, recipient_port):
        print(f"\n📁 {recipient_name} ile dosya transfer modu!")
        print("📝 Komutlar:")
        print("  • Tek dosya göndermek için: <dosya_yolu>")
        print("  • Çoklu dosya göndermek için: /multi <dosya1> <dosya2> ...")
        print("  • Klasör içindeki tüm .txt dosyaları için: /folder <klasör_yolu>")
        print("  • Çıkmak için: exit")
        print("-" * 50)

        while self.chat_active:
            try:
                user_input = input(f"[Dosya]: ").strip()

                if not user_input:
                    continue

                if user_input.lower() == "exit":
                    print("🔚 Dosya transfer modundan çıkılıyor...")
                    self.chat_active = False
                    break

                # Çoklu dosya gönderme
                if user_input.startswith('/multi '):
                    file_paths = user_input[7:].strip().split()
                    if file_paths:
                        self.send_multiple_files(file_paths, recipient_name, recipient_host, recipient_port)
                    else:
                        print("❌ Dosya yolları belirtilmedi! Kullanım: /multi <dosya1> <dosya2> ...")

                # Klasör içindeki .txt dosyaları gönderme
                elif user_input.startswith('/folder '):
                    folder_path = user_input[8:].strip()
                    if folder_path:
                        self.send_txt_files_from_folder(folder_path, recipient_name, recipient_host, recipient_port)
                    else:
                        print("❌ Klasör yolu belirtilmedi! Kullanım: /folder <klasör_yolu>")

                else:
                    # Tek dosya gönder
                    file_path = user_input.strip()
                    if file_path:
                        self.send_file(file_path, recipient_name, recipient_host, recipient_port)
                    else:
                        print("❌ Dosya yolu belirtilmedi!")

            except KeyboardInterrupt:
                print("\n🔚 Dosya transfer modu sonlandırılıyor...")
                self.chat_active = False
                break
            except EOFError:
                print("\n🔚 EOF algılandı, dosya transfer modu sonlandırılıyor...")
                self.chat_active = False
                break
            except Exception as e:
                print(f"❌ Girdi hatası: {e}")

    def send_multiple_files(self, file_paths, recipient_name, recipient_host, recipient_port):
        print(f"📤 {len(file_paths)} dosya gönderiliyor...")
        
        success_count = 0
        for i, file_path in enumerate(file_paths, 1):
            print(f"\n📄 [{i}/{len(file_paths)}] {os.path.basename(file_path)}")
            
            if os.path.exists(file_path):
                try:
                    self.send_file(file_path, recipient_name, recipient_host, recipient_port)
                    success_count += 1
                    time.sleep(0.5)  # Sunucuya biraz nefes vermek için
                except Exception as e:
                    print(f"❌ {file_path} gönderilemedi: {e}")
            else:
                print(f"❌ Dosya bulunamadı: {file_path}")
        
        print(f"\n✅ Toplam {success_count}/{len(file_paths)} dosya başarıyla gönderildi")

    def send_txt_files_from_folder(self, folder_path, recipient_name, recipient_host, recipient_port):
        if not os.path.isdir(folder_path):
            print(f"❌ Klasör bulunamadı: {folder_path}")
            return

        try:
            txt_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.txt')]
            
            if not txt_files:
                print(f"❌ {folder_path} klasöründe .txt dosyası bulunamadı")
                return

            print(f"📁 {folder_path} klasöründe {len(txt_files)} adet .txt dosyası bulundu")
            
            file_paths = [os.path.join(folder_path, f) for f in txt_files]
            self.send_multiple_files(file_paths, recipient_name, recipient_host, recipient_port)

        except Exception as e:
            print(f"❌ Klasör okuma hatası: {e}")


def main():
    try:
        print("=" * 60)
        print("🔐 PGP Secure Chat System with File Transfer")
        print("=" * 60)
        print("1. 📨 Mesaj ve Dosya Alma Modu (Sunucu)")
        print("2. 💬 Sohbet Modu (İstemci)")
        print("3. 📁 Dosya Transfer Modu (İstemci)")
        print("4. ℹ️  Sistem Bilgisi")
        print("=" * 60)

        mode = input("Mod seçin (1/2/3/4): ").strip()

        if mode == "1":
            # Sunucu modu
            peer_name = input("👤 Adınız: ").strip()
            if not peer_name:
                peer_name = "Server"

            host = input("🌐 Sunucu IP (Enter = localhost): ").strip() or "localhost"
            port_input = input("🔌 Port (Enter = 9999): ").strip()
            port = int(port_input) if port_input else 9999

            chat_system = PGPChatSystem(peer_name, host, port)
            chat_system.load_or_create_keys()
            chat_system.get_system_info()
            print()

            try:
                chat_system.start_server()
            except KeyboardInterrupt:
                chat_system.stop_server()

        elif mode == "2":
            # Sohbet modu
            peer_name = input("👤 Adınız: ").strip()
            if not peer_name:
                peer_name = "Client"

            recipient_name = input("👥 Sohbet edeceğiniz kişinin adı: ").strip()
            if not recipient_name:
                recipient_name = "Server"

            recipient_host = input("🌐 Karşı tarafın IP adresi (Enter = localhost): ").strip() or "localhost"
            port_input = input("🔌 Port (Enter = 9999): ").strip()
            recipient_port = int(port_input) if port_input else 9999

            chat_system = PGPChatSystem(peer_name)
            chat_system.load_or_create_keys()
            chat_system.get_system_info()
            print()

            chat_system.connect_and_chat(recipient_name, recipient_host, recipient_port)

        elif mode == "3":
            # Dosya transfer modu
            peer_name = input("👤 Adınız: ").strip()
            if not peer_name:
                peer_name = "FileClient"

            recipient_name = input("👥 Dosya göndereceğiniz kişinin adı: ").strip()
            if not recipient_name:
                recipient_name = "Server"

            recipient_host = input("🌐 Karşı tarafın IP adresi (Enter = localhost): ").strip() or "localhost"
            port_input = input("🔌 Port (Enter = 9999): ").strip()
            recipient_port = int(port_input) if port_input else 9999

            chat_system = PGPChatSystem(peer_name)
            chat_system.load_or_create_keys()
            chat_system.get_system_info()
            print()

            chat_system.file_transfer_mode(recipient_name, recipient_host, recipient_port)

        elif mode == "4":
            # Sistem bilgisi
            peer_name = input("👤 Adınız (bilgi için): ").strip() or "InfoUser"
            chat_system = PGPChatSystem(peer_name)
            chat_system.get_system_info()

        else:
            print("❌ Geçersiz seçim!")

    except KeyboardInterrupt:
        print("\n🛑 Program sonlandırılıyor...")
    except Exception as e:
        print(f"❌ Program hatası: {e}")
    finally:
        print("👋 Güle güle!")


if __name__ == "__main__":
    main()