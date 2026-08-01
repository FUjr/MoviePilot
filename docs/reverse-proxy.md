# 反向代理子目录部署

Docker 镜像支持通过 `NGINX_SUBDIRECTORY` 将 Web 前端和 API 统一挂载到指定子目录。路径可以写成 `moviepilot`、`/moviepilot` 或 `/moviepilot/`，容器启动时会统一规范为 `/moviepilot`。

```yaml
services:
  moviepilot:
    environment:
      NGINX_SUBDIRECTORY: /moviepilot
```

配置后，容器内访问入口为 `http://127.0.0.1:3000/moviepilot/`。反向代理应保留该路径前缀：

```nginx
location /moviepilot/ {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

留空或设置为 `/` 时保持原有根路径部署行为。配置值不支持空格、查询参数或 URL 片段。
