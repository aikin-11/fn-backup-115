FROM docker.m.daocloud.io/library/python:3.12-alpine
RUN apk add --no-cache tzdata coreutils
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
ENV TZ=Asia/Shanghai PYTHONUNBUFFERED=1
VOLUME ["/config", "/backups"]
EXPOSE 8080
CMD ["python", "zip_app.py"]
