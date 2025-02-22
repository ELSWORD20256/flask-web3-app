from flask import Flask, request, jsonify, render_template
import os
import pandas as pd
import joblib
import requests
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from web3 import Web3
from flask_cors import CORS
import json
import base64
import time
import psutil  # 用於監控系統資源使用

# ✅ ChaCha20 加密函數（適用於高度隱私資料）
def chacha20_encrypt(data):
    key = os.urandom(32)  # 產生 256-bit 隨機金鑰
    nonce = os.urandom(16)  # 生成隨機 nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode())  # 加密
    return ciphertext, key, nonce

# AES加密 ( 適用於中度私密性資料)
def aes_encrypt(data):
    key = os.urandom(32)  # 生成256-bit的密鑰
    iv = os.urandom(16)   # 初始化向量
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return ciphertext, key, iv

#  針對不同隱私等級選擇加密方式
def encrypt_based_on_privacy(privacy_level, data):
    if privacy_level == 'High level':
        #print(f"高度隱私 - 使用 ChaCha20 加密")
        encrypted_data, key, nonce = chacha20_encrypt(data)
        return encrypted_data, key, nonce
    elif privacy_level == 'Medium level':
        #print(f"中度隱私 - 使用 AES 加密")
        encrypted_data, key, iv = aes_encrypt(data)
        return encrypted_data, key, iv
    elif privacy_level == 'Low level':
        #print(f" 低度隱私 - 不加密，直接存儲")
        return data.encode(), None, None
    else:
        #print(f"未知的隱私等級 {privacy_level}，不進行加密")
        return data.encode(), None, None


# 定義存儲加密數據的目錄
ENCRYPTED_DATA_FOLDER = os.path.join(os.getcwd(), "encrypted_data")
os.makedirs(ENCRYPTED_DATA_FOLDER, exist_ok=True)

def save_encrypted_data(record_id, encryption_algorithm, encrypted_data, key, extra_param):
    """
    將加密數據存入 JSON 檔案，並標註加密演算法。
    """
    file_path = os.path.join(ENCRYPTED_DATA_FOLDER, "encrypted_data.json")
    
    # 編碼加密數據
    encoded_data = base64.b64encode(encrypted_data).decode()
    key_b64 = base64.b64encode(key).decode() if key else None
    extra_param_b64 = base64.b64encode(extra_param).decode() if extra_param else None
    
    # 構建數據記錄
    record = {
        "record_id": record_id,
        "encryption_algorithm": encryption_algorithm,
        "encrypted_data": encoded_data,
        "key": key_b64,
        "extra_param": extra_param_b64
    }
    
    # 讀取現有數據，並追加新數據
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                existing_data = json.load(f)
        else:
            existing_data = []
    except json.JSONDecodeError:
        existing_data = []
    
    existing_data.append(record)
    
    # 存回檔案
    with open(file_path, "w") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)
    
    print(f"✅ 記錄第 {record_id} 筆加密數據 ({encryption_algorithm}) 存入 {file_path}")


# 初始化 Flask 應用
app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = '/path/to/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 載入模型和編碼器
model = joblib.load(os.path.join(os.getcwd(), "logistic_regression_model.pkl"))
label_encoder_diag_1 = joblib.load(os.path.join(os.getcwd(), "label_encoder_diag_1.pkl"))
label_encoder_diag_2 = joblib.load(os.path.join(os.getcwd(), "label_encoder_diag_2.pkl"))
label_encoder_diag_3 = joblib.load(os.path.join(os.getcwd(), "label_encoder_diag_3.pkl"))
label_encoder_gender = joblib.load(os.path.join(os.getcwd(), "label_encoder_gender.pkl"))
label_encoder_race = joblib.load(os.path.join(os.getcwd(), "label_encoder_race.pkl"))
label_encoder_privacy = joblib.load(os.path.join(os.getcwd(), "label_encoder_privacy.pkl"))


# IPFS 路徑
IPFS_API_URL = 'http://127.0.0.1:5001/api/v0/add'

# Web3 初始化
w3 = Web3(Web3.HTTPProvider(' https://5fda-203-69-229-89.ngrok-free.app'))
with open(os.path.join(os.getcwd(), "contracts", "SecureDataStorage.json"), encoding='utf-8') as f:
    contract_data = json.load(f)
contract_abi = contract_data['abi']
contract_address = '0x37121E996a81dEafB013398538fFDF5DdF3E1c76'
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

current_user_address = None  # 在全域中定義變數

# 檢查 ABI 的內容
#print("ABI 提取結果:")
#print(json.dumps(contract_abi, indent=4))



@app.route('/')
def index():
    return render_template('index.html')


# API: 授權地址
@app.route('/authorize_wallet', methods=['POST'])
def authorize_wallet():
    global current_user_address
    try:
        # 從請求中獲取地址
        wallet_address = request.json.get('wallet_address', '').strip()
        sender_address = request.json.get('sender_address', '').strip()

        #print(f"接收到的 wallet_address: {wallet_address}, 類型: {type(wallet_address)}")
        #print(f"接收到的 sender_address: {sender_address}, 類型: {type(sender_address)}")
        
        # 驗證地址是否以 0x 開頭且長度為 42
        if not wallet_address.startswith('0x') or len(wallet_address) != 42:
            return jsonify({"error": "Invalid wallet address format"}), 400
        
        if not sender_address.startswith('0x') or len(sender_address) != 42:
            return jsonify({"error": "Invalid sender address format"}), 400
        
        # 驗證地址是否為校驗和地址
        if not Web3.is_checksum_address(wallet_address):
            return jsonify({"error": "Address is not a valid checksum address"}), 400
        if not Web3.is_checksum_address(sender_address):
            return jsonify({"error": "Sender address is not a valid checksum address"}), 400

        # 檢查地址是否已被授權
        if contract.functions.authorizedUsers(sender_address).call():
            current_user_address = sender_address  # 更新當前使用者地址
            # 記錄當前使用者地址
            
            return jsonify({"message": f"Address {sender_address} is already authorized and set as the current user", 
                            "default_account": current_user_address}), 200
        
       
        # 執行授權操作
        accounts = w3.eth.accounts
        tx = contract.functions.authorizeUser(sender_address).transact({'from':wallet_address})
        w3.eth.wait_for_transaction_receipt(tx)
        

        # 授權成功後更新當前使用者地址
        current_user_address = sender_address
        #print(f"授權成功！當前的 current_user_address: {current_user_address}")
        

        return jsonify({"message": f"Successfully authorized address {current_user_address}"}), 200
    except Exception as e:
        #print(f"授權過程中發生錯誤: {str(e)}")
        return jsonify({"error": str(e)}), 500
    


@app.route('/upload', methods=['POST'])
def upload_file():

    global current_user_address  # 使用當前被授權的地址
     # 接收發起交易的地址
    

    # 驗證是否存在授權的 current_user_address
    if not current_user_address:
        return jsonify({"error": "No authorized user address. Please authorize a wallet first."}), 400

    # 驗證 current_user_address 是否已被授權
    authorized = contract.functions.authorizedUsers(current_user_address).call()
    if not authorized:
        return jsonify({"error": f"User {current_user_address} is not authorized to upload data."}), 403


    # 開始計算整個流程的效能
    total_start_time = time.time()
    total_cpu_usage = 0
    total_memory_usage = 0
    # 檢查上傳的文件是否存在
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No file selected"}), 400

    # 保存上傳的文件到伺服器
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # 讀取文件並確認內容
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        return jsonify({"message": f"Error reading CSV file: {str(e)}"}), 400

    # 定義特徵欄位
    features = ['patient_nbr', 'diag_1', 'diag_2', 'diag_3', 'age', 'gender', 'race']
    if not set(features).issubset(df.columns):
        return jsonify({"message": "Missing required columns in the uploaded file"}), 400

    X = df[features]

    # 使用之前載入的編碼器進行特徵轉換
    try:
        X['diag_1'] = label_encoder_diag_1.transform(X['diag_1'].astype(str))
        X['diag_2'] = label_encoder_diag_2.transform(X['diag_2'].astype(str))
        X['diag_3'] = label_encoder_diag_3.transform(X['diag_3'].astype(str))
        X['gender'] = label_encoder_gender.transform(X['gender'].astype(str))
        X['race'] = label_encoder_race.transform(X['race'].astype(str))
    
        # 創建標記欄位來指示缺失值
        X['patient_nbr_missing'] = X['patient_nbr'].apply(lambda x: 1 if x == '-999' or x == '0' else 0)
        X['diag_1_missing'] = X['diag_1'].apply(lambda x: 1 if x == '-999' or x == '0' else 0)
        X['diag_2_missing'] = X['diag_2'].apply(lambda x: 1 if x == '-999' or x == '0' else 0)
        X['diag_3_missing'] = X['diag_3'].apply(lambda x: 1 if x == '-999' or x == '0' else 0)
        X['gender_missing'] = X['gender'].apply(lambda x: 1 if x == '-999' or x == '0' else 0)
    except Exception as e:
        return jsonify({"message": f"Error during feature encoding: {str(e)}"}), 400

    # 進行隱私等級的預測
    try:
        simulated_features = X
        privacy_predictions = model.predict(simulated_features)
        privacy_levels = label_encoder_privacy.inverse_transform(privacy_predictions)

        # 將預測結果轉換為文字描述
        privacy_descriptions = {
            0: "High level",
            1: "Medium level",
            2: "Low level"
        }
        predicted_privacy_descriptions = [privacy_descriptions.get(level, "未知") for level in privacy_levels]
        X['predicted_privacy_level'] = privacy_levels
        X['predicted_privacy_description'] = predicted_privacy_descriptions
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # 處理每一筆資料，進行加密
    encrypted_results = []
    data_to_encrypt = "Sensitive Data Example"

    for i, privacy_level in enumerate(X['predicted_privacy_description']):

        start_time = time.time()  # 開始計算單筆處理的效能
        # 開始監控 CPU 和內存使用
        cpu_start = psutil.cpu_percent(interval=None)
        memory_start = psutil.virtual_memory().percent
        print(f"### 正在處理第 {i+1} 筆資料，隱私等級: {privacy_level} ###")

        # 根據隱私等級進行加密
        try:
            encrypted_data, key, extra_param = encrypt_based_on_privacy(privacy_level, data_to_encrypt)
            #print(f"第 {i+1} 筆 - 加密成功")
        except Exception as e:
            #print(f"第 {i+1} 筆 - 加密失敗，錯誤: {e}")
            continue
        
        # 📝 儲存金鑰、加密參數
        encryption_metadata = {
            "key": base64.b64encode(key).decode() if key else None,
            "extra_param": base64.b64encode(extra_param).decode() if extra_param else None
        }
        encrypted_json = {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "metadata": encryption_metadata
        }
        
        

        # 將加密後的二進制數據進行 Base64 編碼
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        #print(f"第 {i+1} 筆 - 加密資料 (Base64): {encoded_data}")

         # 存檔加密數據
        save_encrypted_data(i + 1, privacy_level, encrypted_data, key, extra_param)
        
        # 將加密後的資料保存成 .txt 文件
        encrypted_file_path = f"{filepath}_row{i+1}.txt"
        try:
            with open(encrypted_file_path, 'w') as f:
                f.write(encoded_data)
            #print(f"第 {i+1} 筆 - 加密文件已保存至: {encrypted_file_path}")
        except Exception as e:
            #print(f"第 {i+1} 筆 - 保存加密文件失敗，錯誤: {e}")
            continue
        
        # 上傳到 IPFS
        try:
            ipfs_hash = upload_to_ipfs(encrypted_file_path)
            #if ipfs_hash:
                #print(f"第 {i+1} 筆 - 文件成功上傳至 IPFS，哈希值: {ipfs_hash}")
            #else:
                #print(f"第 {i+1} 筆 - 上傳至 IPFS 失敗")
                #continue
        except Exception as e:
            print(f"第 {i+1} 筆 - 上傳至 IPFS 發生錯誤，錯誤: {e}")
            continue

        # 記錄到區塊鏈
        try:
            store_to_blockchain(ipfs_hash, privacy_level,current_user_address)
            #print(f"第 {i+1} 筆 - IPFS 哈希值已成功記錄至區塊鏈")
        except Exception as e:
            #print(f"第 {i+1} 筆 - 記錄至區塊鏈失敗，錯誤: {e}")
            continue
        
        # 停止監控並計算使用資源
        cpu_end = psutil.cpu_percent(interval=None)
        memory_end = psutil.virtual_memory().percent

        cpu_usage = cpu_end - cpu_start
        memory_usage = memory_end - memory_start

        total_cpu_usage += cpu_usage
        total_memory_usage += memory_usage

        encrypted_results.append({
            "row": i + 1,
            "privacy_level": privacy_level,
            "encrypted_data": encoded_data,
            "ipfs_hash": ipfs_hash
        })

    total_end_time = time.time()

    # 計算平均資源使用率
    num_records = len(encrypted_results)
    avg_cpu_usage = total_cpu_usage / num_records if num_records > 0 else 0
    avg_memory_usage = total_memory_usage / num_records if num_records > 0 else 0
    print("計時結束")
    print(f"整體處理完成，總耗時: {total_end_time - total_start_time:.2f} 秒")
    print(f"平均 CPU 使用率: {avg_cpu_usage:.2f}%")
    print(f"平均記憶體使用率: {avg_memory_usage:.2f}%")

    return jsonify({
        "message": f"File {filename} uploaded and processed successfully.",
        "encrypted_results": encrypted_results,
        "total_time_taken": total_end_time - total_start_time,
        "avg_cpu_usage": avg_cpu_usage,
        "avg_memory_usage": avg_memory_usage
    })

# 上傳文件到 IPFS 的函數
def upload_to_ipfs(file_path):
    with open(file_path, 'rb') as file:
        response = requests.post(IPFS_API_URL, files={'file': file})
    if response.status_code == 200:
        ipfs_hash = response.json()['Hash']
        #print('文件上傳成功，IPFS 哈希值:', ipfs_hash)
        return ipfs_hash
    else:
        #print('文件上傳到 IPFS 失敗:', response.text)
        return None

# 在區塊鏈上記錄 IPFS 哈希值的函數
def store_to_blockchain(ipfs_hash, privacy_level, from_address):
    try:
        # 驗證輸入的地址
        if not Web3.is_checksum_address(from_address):
            raise ValueError("Invalid checksum address for transaction sender.")

        # 計算哈希值
        data_hash = w3.keccak(text=ipfs_hash)

        # 發起交易，指定發起者地址
        tx = contract.functions.storeData(data_hash, ipfs_hash).transact({'from': from_address})
        
        # 等待交易完成
        w3.eth.wait_for_transaction_receipt(tx)
        #print(f"IPFS 哈希值已記錄到區塊鏈，發起者地址: {from_address}")
        #print(f"📌 記錄時哈希: {w3.to_hex(data_hash)}")
        
    except Exception as e:
       # print(f"記錄到區塊鏈時發生錯誤: {e}")
        raise



@app.route('/check-authorization', methods=['POST'])
def check_authorization():
    try:
        user_address = request.json.get('user_address', '').strip()

        if not user_address.startswith('0x') or len(user_address) != 42:
            return jsonify({"error": "Invalid wallet address format"}), 400

        if not Web3.is_checksum_address(user_address):
            return jsonify({"error": "Address is not a valid checksum address"}), 400

        # 檢查此地址是否已授權
        authorized = contract.functions.authorizedUsers(user_address).call()
        if not authorized:
            return jsonify({"error": f"User {user_address} is not authorized."}), 403

        return jsonify({"message": f"User {user_address} is authorized."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
from eth_utils import to_bytes

@app.route('/download', methods=['POST'])
def download_file():
    try:
        data = request.json
        user_address = data.get('user_address', '').strip()
        ipfs_hash = data.get('ipfs_hash', '').strip()

        if not user_address or not ipfs_hash:
            return jsonify({"error": "User address and IPFS hash are required"}), 400

        # 確保用戶地址為合法的 checksum 地址
        if not Web3.is_checksum_address(user_address):
            return jsonify({"error": "Invalid checksum address"}), 400

        # 確保使用者已授權
        authorized = contract.functions.authorizedUsers(user_address).call()
        if not authorized:
            return jsonify({"error": f"User {user_address} is not authorized to download files."}), 403

        # 驗證 IPFS 哈希是否存在於區塊鏈
        data_hash = w3.keccak(text=ipfs_hash)
        stored_hash = contract.functions.retrieveData(data_hash).call()

        if stored_hash != ipfs_hash:
            return jsonify({"error": "Data integrity check failed! The file may have been tampered with."}), 403

        # 下載 IPFS 檔案
        ipfs_gateway = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
        response = requests.get(ipfs_gateway)

        if response.status_code != 200:
            return jsonify({"error": "Failed to retrieve file from IPFS."}), 500

        return jsonify({
            "message": "✅ File successfully retrieved and verified.",
            "encrypted_data": response.text,
            "time_taken": response.elapsed.total_seconds()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



    
@app.route('/verify', methods=['POST'])
def verify_hash():
    data = request.json
    ipfs_hash = data.get('ipfs_hash')

    try:
        data_hash = w3.keccak(text=ipfs_hash)
        stored_hash = contract.functions.retrieveData(data_hash).call()
        if stored_hash == ipfs_hash:
            return jsonify({"message": "驗證成功，IPFS 哈希存在於區塊鏈"}), 200
        else:
            return jsonify({"message": "驗證失敗，IPFS 哈希不存在於區塊鏈"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
