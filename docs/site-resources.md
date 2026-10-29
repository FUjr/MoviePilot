# 本分支的 V3 站点模块

本分支把原有 Python 站点实现迁到 V3 的 `app/application/site/sites.py`，继续通过
`app.sdk.network.SitesHelper` 和精确兼容路径 `app.helper.sites` 提供接口。
不需要加载 `sites.*.so` 或在应用启动时解密站点数据。

## 对齐版本

- 后端基线：[MoviePilot V3 提交 87561a90d](https://github.com/jxxghp/MoviePilot/commit/87561a90d16e9bc087225c72bbfebe16865b3baa)，后端 v3.2.1。
- 索引数据：[MoviePilot-Resources 提交 f39087929](https://github.com/jxxghp/MoviePilot-Resources/tree/f39087929e7a9b53a710d3429e6df2edef806d9b)，数据版本 3.0.25，共 183 个站点。
- 本地认证实现版本为 3.0.0，与官方认证二进制版本独立；本分支沿用原有权限等级 99 策略。

V3 数据包含新增的 colapt、oldtoons、speedapp、vclib、xdypt，以及音乐分类和
`api_domain`、`login_path`、`media_type`、`userdata_path` 等字段。
这些数据保存在 `user.sites.v3.json`，规则合并时保留扩展字段。

## 接口行为

| 接口 | 本地实现行为 |
| --- | --- |
| `get_indexers` / `async_get_indexers` | 使用 V3 `SiteQueryService`，按优先级返回已配置且启用的站点；异步接口等待异步仓储 |
| `get_indexer` / `async_get_indexer` | 接受完整 URL 或规范域名，匹配主域名及备用域名；可读取停用或尚未配置的站点规则 |
| `get_indexsites` / `get_authsites` | 返回独立副本，供站点表单和插件使用 |
| `add_indexer` | 替换动态规则及其别名，不保留调用方可变对象 |
| `check` | 同一站点的别名共用限流状态；查询不会重置额度，None 表示未配置相应限制 |
| `check_user` | 兼容旧字段和 V3 的 `SITE_PARAMETER` 键名；通过启动层注入的 RequestUtils 端口请求 |

认证接口保留本分支已有的 Sunny、YemaPT 和通用 NexusPHP 客户端，未实现的站点专用认证协议仍可能失败。
离线测试验证调用及数据契约，不代表所有站点真实搜索、登录或官方认证行为均已验证。

## 安装与更新

`moviepilot install resources` 校验源码和 JSON，并清除同目录中会优先于 Python 源码加载的旧原生扩展。
卸载保留源码、JSON 和类型声明，仅清理旧二进制资源。
Docker 构建直接携带源码资源。程序内更新及 Docker DEV 更新只接受包含本分支源码资源的完整后端包；
官方后端归档缺少本地实现时会拒绝安装，避免宿主接口被覆盖。后续请通过 Git 或本分支镜像更新，
失败时沿用 V3 的回滚流程。历史暂存的官方二进制资源包也不能覆盖源码模块。

`AUTO_UPDATE_RESOURCE` 默认关闭。检测到源码站点包时，即使保留此开关的旧配置，也不会请求官方二进制更新清单。
站点数据通过本仓库代码更新发布。

本地覆盖镜像使用 `docker/Dockerfile.local`，基础镜像须匹配 V3 运行时；
`MOVIEPILOT_BASE_IMAGE` 可指定确切基础镜像。GHCR 工作流跟随 `v3` 构建两种架构，实际发布需要另行推送并通过 CI。
