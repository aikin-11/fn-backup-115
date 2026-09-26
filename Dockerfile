FROM docker.m.daocloud.io/library/python:3.12-alpine
RUN apk add --no-cache tzdata coreutils
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY zip_app.py web.html /app/
ENV TZ=Asia/Shanghai PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME ["/config", "/backups"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/progress', timeout=4).read()" || exit 1
CMD ["python", "-u", "zip_app.py"]
