"""
站点认证参数的宿主边界规范化。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Optional, Protocol, TypedDict, cast

from app.schemas.common import JsonData


class SiteAuthHttpPort(Protocol):
    """
    站点认证所需的同步 JSON 请求端口，由启动组合根装配传输实现。
    """

    def get_json(
        self, *, url: str, headers: dict[str, str], timeout: int,
    ) -> tuple[Optional[int], dict[str, JsonData]]:
        """
        请求认证数据并在读取后释放响应。

        :param url: 可信站点资源定义的认证接口地址
        :param headers: 本次认证专用请求头，可能包含凭据
        :param timeout: 单次请求超时秒数
        :return: HTTP 状态码与 JSON 对象；无响应时为 None 和空字典
        :raises ValueError: 成功响应不是 JSON 对象
        """
        ...


_configured_site_auth_http: Optional[SiteAuthHttpPort] = None


def configure_site_auth_http(port: SiteAuthHttpPort) -> None:
    """
    登记当前生命周期使用的站点认证传输端口。
    """
    global _configured_site_auth_http
    _configured_site_auth_http = port


def reset_site_auth_http() -> None:
    """
    清除站点认证传输端口，防止跨生命周期保留旧依赖。
    """
    global _configured_site_auth_http
    _configured_site_auth_http = None


def get_site_auth_http() -> SiteAuthHttpPort:
    """
    取得已装配的站点认证传输；未装配时明确报错。
    """
    if _configured_site_auth_http is None:
        raise RuntimeError("站点认证传输尚未配置")
    return _configured_site_auth_http


class _SiteAuthConfig(TypedDict):
    """
    认证资源公共入口接受的站点配置形状。

    :ivar site: 认证资源清单中的站点标识
    :ivar params: 已按资源契约规范化的认证参数映射
    """

    site: str
    params: dict[str, JsonData]


def normalize_site_auth_params(
    site: Optional[str],
    params: Optional[Mapping[str, JsonData]],
    auth_sites: Mapping[str, JsonData],
) -> dict[str, JsonData]:
    """
    把站点字段名规范化为认证资源使用的站点前缀键名。

    认证资源的公共认证入口按 ``SITE_PARAMETER`` 读取参数，但旧版 API、
    CLI 配置和外部调用方可能提交资源清单中的原始字段名。保留未知字段，
    只将已知站点字段转换为资源契约键名。
    """
    normalized = dict(params or {})
    if not site or not params or not isinstance(auth_sites, Mapping):
        return normalized

    site_config = auth_sites.get(site)
    if not isinstance(site_config, Mapping):
        return normalized
    param_definitions = site_config.get("params")
    if not isinstance(param_definitions, Mapping):
        return normalized

    for raw_key in param_definitions:
        if not isinstance(raw_key, str):
            continue
        env_key = f"{site.upper()}_{raw_key.upper()}"
        if env_key in params:
            normalized[env_key] = params[env_key]
        elif raw_key in params:
            normalized[env_key] = params[raw_key]
        if raw_key != env_key:
            normalized.pop(raw_key, None)
    return normalized


def normalize_site_auth_config(
    auth_config: Optional[Mapping[str, JsonData]],
    auth_sites: Mapping[str, JsonData],
) -> Optional[_SiteAuthConfig]:
    """
    规范化持久化的站点认证配置，兼容旧字段名。
    """
    if not auth_config:
        return None

    site = auth_config.get("site")
    params = auth_config.get("params")
    if not isinstance(site, str) or not isinstance(params, Mapping):
        return None

    normalized = dict(auth_config)
    normalized["params"] = normalize_site_auth_params(site, params, auth_sites)
    return cast(_SiteAuthConfig, normalized)
