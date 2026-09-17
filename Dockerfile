# JSON 数据脱敏工作台 —— 一体化镜像
# 构建：docker build -t json-masking-workbench .
# 运行：docker run -p 8000:8000 -e MASK_SALT=your-secret json-masking-workbench
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 先装依赖，充分利用构建缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码与静态资源
COPY app ./app

# 数据目录（SQLite 仅存规则模板）；容器内初始化，无需外部步骤
ENV DATA_DIR=/data \
    MASK_SALT=local-dev-salt \
    PORT=8000
RUN mkdir -p /data && useradd -r -u 10001 appuser && chown -R appuser /data /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,os;urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PORT','8000')}/api/health\",timeout=2)"

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
