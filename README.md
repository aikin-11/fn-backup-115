# 飞牛 NAS 115 备份容器

一个单容器备份工具：压缩、增量、AES-256 加密、定时执行、Web 配置和日志均内置。115 目标通过 WebDAV 访问。

## 飞牛部署

```bash
git clone https://github.com/aikin-11/fn-backup-115.git
cd fn-backup-115
# 按需修改 docker-compose.yml 中的源目录映射
docker compose up -d --build
```

浏览器访问 `http://飞牛IP:8080`，填写源目录（容器内路径，如 `/data/重要资料`）、115 WebDAV URL、账号密码、备份密码和计划。

首次备份生成完整 tar.gz，后续只打包新增/修改文件。加密使用 AES-256-CBC + PBKDF2。上传成功后默认删除本地归档。
