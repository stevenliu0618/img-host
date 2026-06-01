FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
COPY . .
EXPOSE 8080
CMD sh -c "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8080}"
