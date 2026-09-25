# 飞牛 NAS 115 备份容器

单容器备份工具：tar.gz 压缩、增量备份、AES-256-CBC/PBKDF2 加密、定时执行、Web 配置与任务记录。115 目标通过 OpenList WebDAV 访问。

## 飞牛部署

本仓库的 `docker-compose.yml` 已按当前 NAS 路径配置。将项目放在 `/vol1/1000/存储空间1/docker/115/app` 后执行：

```bash
cd "/vol1/1000/存储空间1/docker/115/app"
docker compose up -d --build
```

打开 `http://192.168.5.23:1124`。当前源目录映射为容器内 `/data/照片`，本地归档目录映射为 `/vol3/1000/存储空间3/备份`。更换 NAS 时需先修改 Compose 中的路径。

当前 OpenList 备份账号的基本路径是 `/115/备份`，因此应用 WebDAV URL 填 `http://192.168.5.23:1999`，远端目录填 `/dav`。

## 备份与恢复

定时任务会扫描源目录，并累计尚未成功备份的新增或修改文件大小。累计达到 1 GiB 后，本轮最多选取约 1 GiB 源文件生成一个归档并上传；单个大于 1 GiB 的文件会单独入包。成功上传后只提交本轮文件的清单，其余变更留待下次扫描。首次全量会在同一次任务中连续按每包约 1 GiB 源文件大小生成并上传，直到全量完成。压缩加密归档会切成每卷不超过 1 GiB 的 `.part0000`、`.part0001` 等分卷，按编号顺序连接后才能解密与解压。备份页面每 2 秒刷新扫描、压缩加密和上传进度；相同进度也写入容器日志。

```bash
read -rsp '归档密码: ' BACKUP_PASSPHRASE; export BACKUP_PASSPHRASE; echo
cat full-YYYYMMDD-HHMMSS-xxxxxx.tar.gz.enc.part* | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE | tar -xz -C /恢复目录
unset BACKUP_PASSPHRASE
```

先恢复完整包，再按时间顺序恢复增量包。当前版本不记录删除操作；源目录删除的文件不会自动从恢复目录删除。未配置远端时总是保留本地分卷；配置远端后，网页开关控制是否保留。
