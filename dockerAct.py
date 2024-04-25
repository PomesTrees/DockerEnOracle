from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Se inicia el flask server
api = Flask(__name__)
messages = {}
cifrado = None
llave = {}
llaveEnc = None

# Ejercicio Hello World
@api.route('/', methods=['GET'])
def hello_world():
        now = datetime.now()
        return jsonify({ "message": f"It's: {now.strftime('%Y-%m-%d %H:%M:%S')}" })

# Ejercicio De Token para Generar Token Nuevo
def generate_key(llaveEnc):
        return Fernet(llaveEnc)
# Ejercicio Token Nuevo
@api.route('/generate-token', methods=['GET'])
def generate_token():
        global llaveEnc, cifrado, llave
        llaveEnc = Fernet.generate_key()
        cifrado = generate_key(llaveEnc)
        llave[llaveEnc] = datetime.now()
        return jsonify({ "message": f"encryption key: {llaveEnc.decode()}" })

# Ejercicio Validar Token
@api.route('/verify-token', methods=['GET'])
def validate_token():
        headers = request.headers
        token = headers.get("Token")
        token = token.encode('utf-8')
        if token in llave and llave[token]+timedelta(hours=1)<datetime.now():
                return jsonify({ "message":"Valid Token" })
        else:
                return jsonify({ "message":"Invalid Token" }), 400

# Ejercicio Borrar Token
@api.route('/delete-token', methods=['POST'])
def delete_token():
        global cifrado
        headers = request.headers
        token = headers.get("Token")
        token = token.encode('utf-8')
        try:
                del llave[token]
                cifrado = None
                return jsonify({ "message": "Successfully deleted token" })
        except:
                return jsonify({ "message": "Token not deleted" }), 400

# Ejercicio Enviar Mensaje Encriptado Con Token
@api.route('/send-message', methods=['POST'])
def send_message():
        global cifrado
        try:
                if cifrado is None:
                        return jsonify({ "message": "Encryption failed" }), 400
                data = request.get_json()
                headers = request.headers
                token = request.headers.get("Token")
                token =  token.encode('utf-8')
                if llave[token]+timedelta(hours = 1) > datetime.now():
                    return jsonify({ "message":"Invalid Token" })
                message = data["message"]
                message_token = token + message.encode()
                encrypted_message = cifrado.encrypt(message_token)
                return jsonify({ "message": f"Encrypted message {encrypted_message.decode()}" })

        except:
                return jsonify({ "message": "Encryption failed" }), 400
                
@api.route('/receive-message', methods=['GET'])
def receive_message():
        global cifrado
        try:
                data = request.get_json()
                encrypted_message = data["message"]
                token = request.headers.get("Token")
                token =token.encode('utf-8')
                if llave[token]+timedelta(hours = 1) > datetime.now():
                    return jsonify({ "message":"Invalid Token" })
                decrypted_message = cifrado.decrypt(encrypted_message.encode())
                decrypted_token = decrypted_message[:len(token)]
                if decrypted_token == token:
                        message = decrypted_message[len(token):].decode()
                        return jsonify({ "message": f"Decrypted message: {message}" })
                else:
                        return jsonify({ "message": "Invalid Token" }), 400
        except Exception as ex:
                return jsonify({ "message": "Decrypting message failed" }), 400

# Puerto
if __name__ == '__main__':
        api.run(debug=True, host='0.0.0.0', port=3001)
