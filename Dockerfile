FROM python:3.12-alpine
RUN apk add --no-cache tar openssl tzdata
WORKDIR /app
COPY . /app
ENV TZ=Asia/Shanghai PYTHONUNBUFFERED=1
VOLUME ["/config", "/backups"]
EXPOSE 8080
CMD ["python", "app.py"]