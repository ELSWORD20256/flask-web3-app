# 使用 Python 3.9 作為基礎映像
FROM python:3.9

# 設定工作目錄
WORKDIR /app

# 複製 requirements.txt 並安裝 Python 依賴
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# 複製 Flask 應用程式檔案
COPY . /app

# 設定 Flask 服務的環境變數
ENV FLASK_APP=testing.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

# 對外開放 Flask 的 5000 端口
EXPOSE 5000

# 啟動 Flask 伺服器
CMD ["flask", "run"]
