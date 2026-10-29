"""
随源码分发的站点索引、认证兼容接口和访问流控。

站点数据使用明文 JSON；持久化查询和 HTTP 传输通过宿主应用服务及注入端口完成。
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.fernet import Fernet

from app.application.configuration import get_configured_system_config
from app.application.site.auth import get_site_auth_http, normalize_site_auth_params
from app.application.site.query import get_configured_site_query_service
from app.domain.site import extract_domain
from app.foundation.singleton import SingletonClass
from app.runtime.log import logger
from app.runtime.settings import get_runtime_setting
from app.schemas.common import JsonData
from app.schemas.site import Site
from app.schemas.types import SystemConfigKey

# 此版本标记本地 Python 认证实现，与官方二进制资源独立发布。
__SITEHELPER_VERSION__ = "3.0.0"
SITES_JSON_FILE = Path(__file__).with_name("user.sites.v3.json")


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    解密二进制数据
    """
    result: bytes = Fernet(key).decrypt(data)
    return result


def encrypt_message(message: str, key: bytes) -> str:
    """
    使用给定的key对消息进行加密，并返回加密后的字符串
    """
    result: str = Fernet(key).encrypt(message.encode("utf-8")).decode("utf-8")
    return result


def hash_sha256(message: str) -> str:
    """
    对字符串做hash运算
    """
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def nexusphp_encrypt(data_str: str, key: bytes) -> str:
    """
    NexusPHP加密

    AES-256-CBC + PKCS7 加密数据，MAC 使用 HMAC-SHA256(base64(iv)+base64(value))，
    输出 base64(JSON{iv, value, mac, tag})。
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    value = cipher.encrypt(pad(data_str.encode("utf-8"), 16))
    iv_b64 = base64.b64encode(iv).decode("utf-8")
    val_b64 = base64.b64encode(value).decode("utf-8")
    mac = hmac.new(key, (iv_b64 + val_b64).encode("utf-8"), hashlib.sha256).hexdigest()
    payload = json.dumps({"iv": iv_b64, "value": val_b64, "mac": mac, "tag": ""})
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


class SiteRateLimiter:
    """
    在线程锁内实施固定窗口次数限制和相邻请求的最小间隔。

    :param limit_interval: 统计窗口秒数，None 或非正数禁用窗口限制
    :param limit_count: 窗口内最大请求数，None 或非正数禁用窗口限制
    :param limit_seconds: 请求最小间隔秒数，None 或非正数禁用间隔限制
    """

    def __init__(self, limit_interval: Optional[int], limit_count: Optional[int],
                 limit_seconds: Optional[int]) -> None:
        """
        规范化可空的流控参数，拒绝请求不消耗额度或推迟恢复时间。
        """
        self._limits = tuple(max(0, int(value or 0)) for value in (limit_interval, limit_count, limit_seconds))
        self._last_access_time: Optional[float] = None
        self._window_start: Optional[float] = None
        self._access_count = 0
        self._lock = threading.Lock()

    @property
    def limits(self) -> tuple[int, ...]:
        """
        返回用于判断是否需要重建流控器的规范化配置。
        """
        return self._limits

    def check_rate_limit(self) -> tuple[bool, str]:
        """
        预留一次访问额度；触发限制时返回 True 和说明，否则返回 False。
        """
        with self._lock:
            now = time.monotonic()
            interval, count, seconds = self._limits
            if seconds and self._last_access_time is not None and now - self._last_access_time < seconds:
                return True, f"触发流控规则，访问间隔不得小于 {seconds} 秒"
            if interval and count:
                if self._window_start is None or now - self._window_start >= interval:
                    self._window_start = now
                    self._access_count = 0
                if self._access_count >= count:
                    return True, f"触发流控规则，{interval} 秒内访问次数不得超过 {count} 次"
                self._access_count += 1
            self._last_access_time = now
            return False, ""


class _SiteAuthHandle:
    """
    保留本地实现的站点认证协议，通过注入端口访问认证接口。
    """

    @staticmethod
    def authenticate(site: str, siteconf: dict[str, JsonData], params: dict[str, JsonData]) -> tuple[bool, str]:
        """
        分发站点认证，返回远端校验结果；缺少凭据或站点地址时不发请求。
        """
        headers = {"User-Agent": get_runtime_setting("USER_AGENT")}
        if site == "sunny":
            if not params.get("apikey"):
                return False, "API Key 未设置"
            headers["Authorization"] = f"Bearer {params['apikey']}"
            url = f"{siteconf.get('api_url') or 'https://api.sunnypt.top/api/v1/mp'}/user/info"
        elif site == "yemapt":
            if not params.get("uid") or not params.get("auth"):
                return False, "UID 或 Auth 未设置"
            headers["Authorization"] = str(params["auth"])
            domain = str(siteconf.get("domain") or "https://www.yemapt.org/")
            url = f"{domain.rstrip('/')}/api.php?{urlencode({'action': 'getuserinfo', 'uid': params['uid']})}"
        else:
            if not params.get("passkey"):
                return False, "此认证协议需要 passkey"
            domain = str(siteconf.get("domain") or "")
            if not domain:
                return False, "此站点尚未配置认证接口"
            query = urlencode({"action": "getuserinfo", "passkey": params["passkey"]})
            url = f"{domain.rstrip('/')}/api.php?{query}"
        status_code, data = get_site_auth_http().get_json(url=url, headers=headers, timeout=15)
        if status_code != 200:
            return False, f"请求失败，状态码：{status_code if status_code is not None else '无响应'}"
        if site == "sunny":
            details = data.get("data") or {}
            accepted = bool(data.get("success") and isinstance(details, dict) and details.get("can_download"))
        else:
            accepted = data.get("status") == "success"
        return accepted, "认证成功" if accepted else "站点凭据校验失败或无下载权限"


class SitesHelper(metaclass=SingletonClass):
    """
    提供 V3 宿主和旧插件共用的站点资源接口。

    本地权限策略沿用此 fork 的等级 99，远端认证结果仍按真实返回值报告。
    """

    def __init__(self) -> None:
        """
        加载源码附带的资源，不在构造阶段访问数据库或网络。
        """
        self._auth_level = 99
        self._auth_version = __SITEHELPER_VERSION__
        self._indexer_version = ""
        self._authsites = copy.deepcopy(_AUTHSITES_DATA)
        self._indexers: dict[str, dict[str, Any]] = {}
        self._indexers_by_domain: dict[str, dict[str, Any]] = {}
        self._ratelimiters: dict[str, SiteRateLimiter] = {}
        self._limiter_domains: dict[str, str] = {}
        self._lock = threading.RLock()
        self._load_resources()

    def _load_resources(self) -> None:
        """
        加载 V3 明文资源，保留未知字段并为主域名及备用域名建立索引。
        """
        with SITES_JSON_FILE.open(encoding="utf-8") as stream:
            data = json.load(stream)
        for site_id, conf in data["indexers"].items():
            self.add_indexer({**conf, "id": conf.get("id") or site_id})
        self._indexer_version = str(data["version"])
        for site_id, conf in self._authsites.items():
            resource = self._indexers.get(site_id)
            # 旧认证表只含表单和图标；认证 URL 取可信资源或图标的来源，不采用用户提交的地址。
            origin = urlsplit(conf.get("icon") or "")
            conf["domain"] = resource["domain"] if resource else f"{origin.scheme}://{origin.netloc}/"
        logger.info("本地站点资源版本：%s", self._indexer_version)

    @property
    def auth_level(self) -> int:
        """
        返回此 fork 的本地权限等级。
        """
        return self._auth_level

    @property
    def auth_version(self) -> str:
        """
        返回本地 Python 认证实现版本。
        """
        return self._auth_version

    @property
    def indexer_version(self) -> str:
        """
        返回随源码分发的站点索引数据版本。
        """
        return self._indexer_version

    def _resource_conf(self, domain: str) -> Optional[dict[str, Any]]:
        """
        按主域名或备用域名取得资源副本，避免运行配置污染内置规则。
        """
        with self._lock:
            entry = self._indexers_by_domain.get(extract_domain(domain))
            return copy.deepcopy(self._indexers.get(entry["id"])) if entry else None

    def _configured_indexers(self, sites: list[Site]) -> list[dict[str, Any]]:
        """
        按仓储优先级投影已配置、已启用且存在索引规则的站点。
        """
        result = []
        for site in sites:
            if site.is_active is False:
                continue
            conf = self._resource_conf(site.domain or site.url or "")
            if conf:
                result.append(self._merge_site_conf(conf, site))
        return result

    def get_indexers(self) -> list[dict[str, JsonData]]:
        """
        同步返回已配置且启用的站点，按站点优先级排序。
        """
        return self._configured_indexers(get_configured_site_query_service().list_ordered_sync())

    async def async_get_indexers(self) -> list[dict[str, JsonData]]:
        """
        使用异步查询返回已配置且启用的站点，不在事件循环中执行同步查询。
        """
        return self._configured_indexers(await get_configured_site_query_service().list_ordered())

    def _indexer_from_sites(self, domain: str, sites: list[Site]) -> Optional[dict[str, Any]]:
        """
        按主域名或别名匹配配置；未添加的站点仍可读取内置规则。
        """
        conf = self._resource_conf(domain)
        if not conf:
            return None
        for site in sites:
            configured = self._resource_conf(site.domain or site.url or "")
            if configured and configured["id"] == conf["id"]:
                return self._merge_site_conf(conf, site)
        return copy.deepcopy(conf)

    def get_indexer(self, domain: str) -> Optional[dict[str, JsonData]]:
        """
        同步按完整地址或裸域名返回索引配置，包括停用站点。
        """
        return self._indexer_from_sites(domain, get_configured_site_query_service().list_ordered_sync())

    async def async_get_indexer(self, domain: str) -> Optional[dict[str, JsonData]]:
        """
        异步按完整地址或裸域名返回索引配置，包括停用站点。
        """
        return self._indexer_from_sites(domain, await get_configured_site_query_service().list_ordered())

    def get_indexsites(self) -> dict[str, dict[str, JsonData]]:
        """
        返回全部支持站点及别名的独立副本，供添加站点和插件使用。
        """
        with self._lock:
            return copy.deepcopy(self._indexers_by_domain)

    def get_authsites(self) -> dict[str, dict[str, JsonData]]:
        """
        返回认证表单的独立副本。
        """
        return copy.deepcopy(self._authsites)

    def add_indexer(self, indexer: dict[str, JsonData]) -> None:
        """
        添加或替换索引规则和全部别名，不保留调用方可变对象或过期别名。
        """
        site_id = indexer.get("id")
        if not isinstance(site_id, str) or not site_id:
            return
        with self._lock:
            self._indexers[site_id] = copy.deepcopy(indexer)
            for domain, old_entry in self._indexers_by_domain.items():
                if old_entry["id"] == site_id:
                    self._limiter_domains.pop(domain, None)
            self._indexers_by_domain = {
                key: entry for key, entry in self._indexers_by_domain.items() if entry["id"] != site_id
            }
            entry = {"id": site_id, "name": indexer.get("name", ""),
                     "url": indexer.get("domain", ""), "public": bool(indexer.get("public"))}
            extra_domains = indexer.get("ext_domains")
            addresses = [indexer.get("domain"), *(extra_domains if isinstance(extra_domains, list) else [])]
            for address in addresses:
                if not isinstance(address, str):
                    continue
                domain = extract_domain(address)
                if domain:
                    self._indexers_by_domain[domain] = entry

    def _merge_site_conf(self, conf: dict[str, Any], site_info: Site) -> dict[str, Any]:
        """
        合并站点凭据和运行参数；爬虫基础地址须保留协议和路径。
        """
        indexer = copy.deepcopy(conf)
        indexer.update(site_info.model_dump(exclude={"domain", "url", "public", "name"}))
        indexer["name"] = site_info.name or conf.get("name")
        indexer["domain"] = site_info.url or conf["domain"]
        indexer["url"] = indexer["domain"]
        indexer["public"] = bool(site_info.public or conf.get("public"))
        self._configure_limiter(extract_domain(indexer["domain"]), indexer)
        with self._lock:
            for address in [conf["domain"], *(conf.get("ext_domains") or []), site_info.domain, indexer["domain"]]:
                self._limiter_domains[extract_domain(address)] = extract_domain(indexer["domain"])
        return indexer

    def _configure_limiter(self, domain: str, indexer: dict[str, Any]) -> None:
        """
        配置未变化时复用流控历史，禁用限制时移除旧状态。
        """
        limits = tuple(max(0, int(indexer.get(key) or 0))
                       for key in ("limit_interval", "limit_count", "limit_seconds"))
        with self._lock:
            if not any(limits):
                self._ratelimiters.pop(domain, None)
            elif domain not in self._ratelimiters or self._ratelimiters[domain].limits != limits:
                self._ratelimiters[domain] = SiteRateLimiter(*limits)

    def check(self, domain: str) -> tuple[bool, str]:
        """
        检查并预留站点访问额度，主域名、完整地址和别名共用同一站点状态。
        """
        domain = extract_domain(domain)
        with self._lock:
            known_domain = self._limiter_domains.get(domain)
        if known_domain is None:
            self.get_indexer(domain)
        with self._lock:
            limiter = self._ratelimiters.get(self._limiter_domains.get(domain, domain))
        return limiter.check_rate_limit() if limiter else (False, "")

    def check_user(self, site: Optional[str] = None,
                   params: Optional[dict[str, JsonData]] = None) -> tuple[bool, str]:
        """
        校验站点凭据，兼容原始字段和 V3 的 SITE_PARAMETER 参数键名。

        :param site: 认证站点标识；省略时先读取 AUTH_SITE，再读取持久化配置
        :param params: 显式提供的认证字段；省略时使用对应来源的配置
        :return: 认证成功标记及不含凭据的结果说明
        """
        if not site:
            site = get_runtime_setting("AUTH_SITE") or ""
            if site:
                params = {key: os.environ.get(f"{site.upper()}_{key.upper()}", "")
                          for key in self._authsites.get(site, {}).get("params", {})}
            else:
                auth_conf = get_configured_system_config().get(SystemConfigKey.UserSiteAuthParams) or {}
                site, params = auth_conf.get("site") or "", auth_conf.get("params") or {}
        siteconf = self._authsites.get(site)
        if not siteconf:
            return False, f"未找到认证站点：{site}"
        normalized = normalize_site_auth_params(site, params, self._authsites)
        raw_params = {key: normalized.get(f"{site.upper()}_{key.upper()}") for key in siteconf["params"]}
        try:
            return _SiteAuthHandle.authenticate(site, siteconf, raw_params)
        except Exception as error:
            # 传输异常可能携带带密钥的完整 URL，只记录异常类型。
            logger.warning("%s 认证请求失败：%s", site, type(error).__name__)
            return False, "站点认证请求失败"


_AUTHSITES_DATA: dict[str, dict[str, Any]] = {
    "hhclub": {
        "name": "HHClub", "icon": "https://hhanclub.net/favicon.ico",
        "params": {
            "username": {"name": "用户名", "type": "text", "placeholder": "username",
                         "tooltip": "站点登录使用的用户名"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "audiences": {
        "name": "Audiences", "icon": "https://audiences.me/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid", "convert": "int",
                    "tooltip": "站点用户UID，打开站点个人信息页面，在地址栏id=后面的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "hddolby": {
        "name": "HDDolby", "icon": "https://www.hddolby.com/favicon.ico",
        "params": {
            "id": {"name": "用户ID", "type": "text", "placeholder": "uid",
                   "tooltip": "站点用户UID，登录后用户名称UID:后面的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "zmpt": {
        "name": "ZmPT", "icon": "https://zmpt.cc/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面，在地址栏id=后面的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "freefarm": {
        "name": "FreeFarm", "icon": "https://pt.0ff.cc/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "hdfans": {
        "name": "HDFans", "icon": "https://hdfans.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "wintersakura": {
        "name": "WinterSakura", "icon": "https://wintersakura.net/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "leaves": {
        "name": "Leaves", "icon": "https://leaves.red/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "ptba": {
        "name": "PTBA", "icon": "https://1ptba.com/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "icc2022": {
        "name": "ICC2022", "icon": "https://www.icc2022.com/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "xingtan": {
        "name": "杏坛", "icon": "https://xingtan.one/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "ptvicomo": {
        "name": "象站", "icon": "https://ptvicomo.net/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "agsvpt": {
        "name": "AGSVPT", "icon": "https://www.agsvpt.com/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "hdkyl": {
        "name": "麒麟", "icon": "https://www.hdkyl.in/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "qingwa": {
        "name": "青蛙", "icon": "https://www.qingwapt.com/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "discfan": {
        "name": "DiscFan", "icon": "https://discfan.net/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "haidan": {
        "name": "海胆之家", "icon": "https://www.haidan.cc/public/pic/favicon.ico",
        "params": {
            "id": {"name": "用户ID", "type": "text", "placeholder": "uid",
                   "tooltip": "站点用户UID，打开站点个人信息页面后查看地址栏id=后面的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "rousi": {
        "name": "Rousi", "icon": "https://rousi.zip/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "sunny": {
        "name": "Sunny", "icon": "https://sunnypt.top/favicon.ico",
        "params": {
            "apikey": {"name": "API Key", "type": "password", "placeholder": "API Key",
                       "tooltip": "在站点控制面板中获取 MoviePilot API Key"},
        },
    },
    "ptcafe": {
        "name": "咖啡", "icon": "https://ptcafe.club/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "ptzone": {
        "name": "PTZone", "icon": "https://ptzone.xyz/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "kufei": {
        "name": "库非", "icon": "https://kufei.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "yemapt": {
        "name": "YemaPT", "icon": "https://36af697e.sardine-ui.pages.dev/icons/icons8-mustang-96.png",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "UID",
                    "tooltip": "站点 个人面板->详情->个人详情 中获取UID"},
            "auth": {"name": "密钥", "type": "password", "placeholder": "auth",
                     "tooltip": "站点 个人面板->详情->安全设定 中获取auth"},
        },
    },
    "hspt": {
        "name": "回声", "icon": "https://hspt.club/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "xingyunge": {
        "name": "星陨阁", "icon": "https://xingyunge.top/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "cspt": {
        "name": "财神", "icon": "https://cspt.cc/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "tmpt": {
        "name": "唐门", "icon": "https://tmpt.top/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "raingfh": {
        "name": "雨", "icon": "https://raingfh.top/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "gtkpw": {
        "name": "GTK", "icon": "https://pt.gtkpw.xyz/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "ptlgs": {
        "name": "PTLGS", "icon": "https://ptlgs.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "hdbao": {
        "name": "HDBAO", "icon": "https://hdbao.cc/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "sewerpt": {
        "name": "下水道", "icon": "https://sewerpt.com/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "ptskit": {
        "name": "PTS", "icon": "https://www.ptskit.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "13city": {
        "name": "13City", "icon": "https://13city.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "lajidui": {
        "name": "LaJiDui", "icon": "https://pt.lajidui.top/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "cangbao": {
        "name": "藏宝阁", "icon": "https://cangbao.ge/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "hxpt": {
        "name": "好学", "icon": "https://www.hxpt.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "longpt": {
        "name": "LongPT", "icon": "https://longpt.org/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "playletpt": {
        "name": "Playlet", "icon": "https://playlet.cc/favicon.ico",
        "params": {
            "uid": {"name": "用户ID", "type": "text", "placeholder": "uid",
                    "tooltip": "站点用户UID，打开站点个人信息页面用户ID/UID的数字"},
            "passkey": {"name": "密钥", "type": "password", "placeholder": "passkey",
                        "tooltip": "在站点控制面板->密钥处获取"},
        },
    },
    "iyuu": {
        "name": "IYUU", "icon": "https://iyuu.cn/static/logo/logo.png",
        "params": {
            "sign": {"name": "用户令牌", "type": "password", "placeholder": "IYUUXXX",
                     "tooltip": "登录IYUU使用的用户名，需要先完成IYUU站点认证"},
        },
    },
}
