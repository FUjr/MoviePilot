"""
站点资源模块（闭源 sites.so 的纯 Python 还原版）

由逆向分析还原，接口与 Cython 闭源版（app.helper.sites，v2.4.9）保持一致。
数据资源：user.sites.v2.json（解密后的明文配置），由本模块直接加载，
不再依赖 Fernet 加密、不再依赖站点用户认证门控（auth_level 固定为最高级别 99）。

与闭源版的差异：
- 数据文件为明文 JSON（user.sites.v2.json），无加密。
- auth_level 固定为最高级别 99（站点&特殊密钥认证可见），所有功能开箱即用。
- 认证/索引的远程站点交互逻辑还原为可读实现。
"""

import abc
import base64
import copy
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from app.core.config import settings
from app.db.site_oper import SiteOper
from app.db.models import Site
from app.log import logger
from app.utils.http import RequestUtils
from app.utils.string import StringUtils

# 资源版本号（与闭源版编译常量一致）
__SITEHELPER_VERSION__ = "2.4.9"
__PUBKEY_TEMPLATE__ = "\n-----BEGIN PUBLIC KEY-----\n{publicKey}\n-----END PUBLIC KEY-----\n"

# Fernet 密钥（逆向还原的编译期常量，仅用于兼容旧版加密 .bin）
__FERNET_KEY__ = b"c1qlByOVxi1-AnpLlYqJwP74XV9mF4GpKWUyjW1dXL8="

# 站点索引配置数据文件（明文 JSON）
SITES_JSON_FILE = Path(__file__).parent / "user.sites.v2.json"


# ============================================================
# 模块级加密函数
# ============================================================

def decrypt(data: bytes, key: bytes) -> bytes:
    """
    解密二进制数据
    """
    return Fernet(key).decrypt(data)


def encrypt_message(message: str, key: bytes) -> str:
    """
    使用给定的key对消息进行加密，并返回加密后的字符串
    """
    return Fernet(key).encrypt(message.encode("utf-8")).decode("utf-8")


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


# ============================================================
# 单例与流控
# ============================================================

class SiteSingleton(abc.ABCMeta):
    """
    站点资源单例元类
    """
    _instances: Dict[type, Any] = {}

    def __call__(cls, *args: Any, **kwargs: Any):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class SiteRateLimiter:
    """
    站点访问流控器

    :param limit_interval: 单位时间（秒）
    :param limit_count: 单位时间内访问次数
    :param limit_seconds: 访问间隔（秒）
    """

    def __init__(self, limit_interval: int, limit_count: int, limit_seconds: int):
        self._limit_interval = limit_interval
        self._limit_count = limit_count
        self._limit_seconds = limit_seconds
        self._last_access_time = 0.0
        self._access_count = 0
        self._lock = threading.Lock()

    def check_rate_limit(self) -> Tuple[bool, str]:
        """
        检查是否超出访问频率控制
        :return: 超出返回True，否则返回False，超出时返回错误信息
        """
        with self._lock:
            now = time.time()
            if self._limit_seconds and now - self._last_access_time < self._limit_seconds:
                return True, f"触发流控规则，访问间隔不得小于 {self._limit_seconds} 秒"
            if self._limit_interval and self._limit_count:
                if now - self._last_access_time >= self._limit_interval:
                    self._access_count = 0
                self._access_count += 1
                if self._access_count > self._limit_count:
                    last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._last_access_time))
                    return True, (f"触发流控规则，{self._limit_interval} 秒内访问次数不得超过 "
                                  f"{self._limit_count} 次，上次访问时间：{last}")
            self._last_access_time = now
            return False, ""


# ============================================================
# 站点认证客户端
# ============================================================

class _SiteAuthHandle:
    """
    站点认证处理

    - sunny: 通过 Sunny PT API 校验 API Key 及下载权限
    - yemapt: 通过 YemaPT 用户信息接口校验 UID + Auth
    - 其余: NexusPHP 系 passkey/用户名认证
    """

    def __init__(self, authsites: Dict[str, dict]):
        self._authsites = authsites

    def get(self, site: str) -> Optional[dict]:
        """获取指定认证站点配置，不存在时返回 None"""
        return self._authsites.get(site)

    def info(self) -> Dict[str, dict]:
        """获取可公开展示的认证站点及表单配置"""
        return self._authsites

    def __sunnypt_auth(self, siteconf: dict, params: dict) -> Tuple[bool, str]:
        """
        通过用户信息接口验证 Sunny PT API Key 和下载权限
        """
        apikey = params.get("apikey")
        if not apikey:
            return False, "API Key 未设置"
        api_url = siteconf.get("api_url") or "https://api.sunnypt.top/api/v1/mp"
        try:
            res = RequestUtils(headers={"Authorization": f"Bearer {apikey}"}).get_res(
                f"{api_url}/user/info", timeout=15)
            if res and res.status_code == 200:
                data = res.json()
                if data.get("success") and data.get("data", {}).get("can_download"):
                    return True, "Sunny PT 认证成功（API Key）"
                return False, data.get("message") or "API Key 无效或无下载权限"
            return False, f"请求失败，状态码：{res.status_code if res else '无响应'}"
        except Exception as err:
            return False, str(err)

    def __yemapt_auth(self, siteconf: dict, params: dict) -> Tuple[bool, str]:
        """
        通过用户信息接口验证 YemaPT UID 和 Auth
        """
        uid = params.get("uid")
        auth = params.get("auth")
        if not uid or not auth:
            return False, "UID 或 Auth 未设置"
        domain = siteconf.get("domain") or "https://www.yemapt.org/"
        try:
            res = RequestUtils(headers={"Authorization": f"{auth}", "User-Agent": settings.USER_AGENT}).get_res(
                f"{domain}api.php?action=getuserinfo&uid={uid}", timeout=15)
            if res and res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    return True, "YemaPT 认证成功"
                return False, data.get("message") or "UID/Auth 校验失败"
            return False, f"错误码：{res.status_code if res else '无响应'}"
        except Exception as err:
            return False, str(err)

    def __nexusphp_auth(self, siteconf: dict, params: dict) -> Tuple[bool, str]:
        """
        NexusPHP 系站点 passkey 认证
        """
        passkey = params.get("passkey")
        if not passkey:
            return False, "passkey 未设置"
        domain = siteconf.get("domain", "")
        try:
            res = RequestUtils(headers={"User-Agent": settings.USER_AGENT}).get_res(
                f"{domain}api.php?action=getuserinfo&passkey={passkey}", timeout=15)
            if res and res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    return True, "认证成功"
                return False, data.get("message") or "passkey 校验失败"
            return False, f"错误码：{res.status_code if res else '无响应'}"
        except Exception as err:
            return False, str(err)


# ============================================================
# 主类
# ============================================================

class SitesHelper(metaclass=SiteSingleton):
    """
    站点资源助手：加载站点索引配置、用户认证、站点流控

    还原自闭源版 app.helper.sites.SitesHelper（v2.4.9）
    """

    def __init__(self):
        # 最高认证级别 99：站点&特殊密钥认证可见，满足所有插件/功能鉴权
        self._auth_level: int = 99
        self._auth_version: str = ""
        self._indexer_version: str = ""
        self._authsites: Dict[str, dict] = {}
        self._indexers: Dict[str, dict] = {}
        self._indexers_by_domain: Dict[str, dict] = {}
        self._ratelimiters: Dict[str, SiteRateLimiter] = {}
        self._lock = threading.RLock()
        self._load_resources()

    # ---------- 资源加载 ----------

    def _load_resources(self):
        """
        加载站点索引配置
        """
        self._authsites = self._load_authsites()
        self._auth_version = __SITEHELPER_VERSION__

        try:
            if SITES_JSON_FILE.exists():
                with open(SITES_JSON_FILE, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                self._indexers = data.get("indexers") or {}
                self._indexer_version = data.get("version") or ""
            else:
                logger.warn(f"站点资源文件不存在：{SITES_JSON_FILE}")
        except Exception as err:
            logger.error(f"加载站点索引配置失败：{err}")
            self._indexers = {}

        # 建立域名索引（含 ext_domains 别名）
        for site_id, conf in self._indexers.items():
            domain = StringUtils.get_url_domain(conf.get("domain") or "")
            if not domain:
                continue
            entry = {
                "id": conf.get("id") or site_id,
                "name": conf.get("name", ""),
                "url": conf.get("domain", ""),
                "public": conf.get("public", False),
            }
            self._indexers_by_domain[domain] = entry
            for ext in conf.get("ext_domains") or []:
                ext_domain = StringUtils.get_url_domain(ext)
                if ext_domain:
                    self._indexers_by_domain[ext_domain] = entry

        logger.info(f"认证资源版本：{self._auth_version}")
        logger.info(f"站点资源版本：{self._indexer_version}")

    def _load_authsites(self) -> Dict[str, dict]:
        """
        认证站点配置（还原自闭源版 .so 内置数据）
        """
        return _AUTHSITES_DATA

    # ---------- 属性 ----------

    @property
    def auth_level(self) -> int:
        """获取用户权限等级"""
        return self._auth_level

    @property
    def auth_version(self) -> str:
        """获取认证资源版本"""
        return self._auth_version

    @property
    def indexer_version(self) -> str:
        """获取站点资源版本"""
        return self._indexer_version

    # ---------- 站点查询 ----------

    def get_indexers(self) -> List[dict]:
        """
        获取所有站点索引配置，包括站点属性
        """
        ret: List[dict] = []
        seen: set = set()
        for domain, entry in self._indexers_by_domain.items():
            site_id = entry.get("id")
            if site_id in seen:
                continue
            seen.add(site_id)
            conf = self._indexers.get(site_id)
            if not conf:
                continue
            site_info = self._find_site_by_config(conf)
            indexer = self._merge_site_conf(conf, site_info)
            if indexer:
                ret.append(indexer)
        return ret

    def _find_site_by_config(self, conf: dict) -> Optional[Site]:
        """
        按索引器配置匹配数据库站点。

        数据库站点记录存于其登录域名（可能不同于索引器主域名），
        需遍历索引器全部已知域名（主域名 + ext_domains）逐一匹配。
        """
        domains = []
        if conf.get("domain"):
            domains.append(conf["domain"])
        for ext in conf.get("ext_domains") or []:
            domains.append(ext)
        for raw_domain in domains:
            site_info = SiteOper().get_by_domain(raw_domain)
            if site_info:
                return site_info
            # 兼容去除 scheme 的域名
            site_info = SiteOper().get_by_domain(StringUtils.get_url_domain(raw_domain))
            if site_info:
                return site_info
        return None

    async def async_get_indexers(self) -> List[dict]:
        """
        异步获取所有站点索引配置，包括站点属性
        """
        return self.get_indexers()

    def get_indexer(self, domain: str) -> Optional[dict]:
        """
        获取站点索引配置，包括站点属性
        """
        entry = self._indexers_by_domain.get(domain)
        if not entry:
            return None
        conf = self._indexers.get(entry.get("id"))
        if not conf:
            return None
        site_info = self._find_site_by_config(conf)
        return self._merge_site_conf(conf, site_info)

    async def async_get_indexer(self, domain: str) -> Optional[dict]:
        """
        异步获取站点索引配置，包括站点属性
        """
        return self.get_indexer(domain)

    def get_indexsites(self) -> dict:
        """
        查询所有索引站点信息
        """
        return copy.deepcopy(self._indexers_by_domain)

    def get_authsites(self) -> dict:
        """
        查询所有认证参数
        """
        return copy.deepcopy(self._authsites)

    def add_indexer(self, indexer: dict):
        """
        添加站点索引配置
        """
        site_id = indexer.get("id")
        if not site_id:
            return
        self._indexers[site_id] = indexer
        domain = StringUtils.get_url_domain(indexer.get("domain") or "")
        if domain:
            self._indexers_by_domain[domain] = {
                "id": site_id,
                "name": indexer.get("name", ""),
                "url": indexer.get("domain", ""),
                "public": indexer.get("public", False),
            }

    # ---------- 站点属性合并 ----------

    def _merge_site_conf(self, conf: dict, site_info: Optional[Site]) -> Optional[dict]:
        """
        合并站点属性

        将索引器配置与数据库站点属性（cookie、ua、proxy、优先级等）合并
        """
        if not conf:
            return None
        indexer = copy.deepcopy(conf)
        if site_info:
            # 站点已配置到数据库：使用数据库站点数字 ID，
            # 与 IndexerSites/RssSites 等按数据库 ID 选择站点的逻辑保持一致
            indexer["id"] = site_info.id
            indexer["name"] = site_info.name or indexer.get("name")
            site_url = site_info.url or indexer.get("domain")
            indexer["url"] = site_url
            # 爬虫把 domain 当作基础 URL 拼接请求路径，不能使用数据库中的裸域名键。
            indexer["domain"] = site_url
            indexer["cookie"] = site_info.cookie
            indexer["ua"] = site_info.ua
            indexer["apikey"] = site_info.apikey
            indexer["token"] = site_info.token
            indexer["proxy"] = site_info.proxy
            indexer["pri"] = site_info.pri
            indexer["downloader"] = site_info.downloader
            indexer["rss"] = site_info.rss
            indexer["filter"] = site_info.filter
            indexer["render"] = site_info.render
            indexer["timeout"] = site_info.timeout
            indexer["public"] = bool(site_info.public or indexer.get("public"))
            indexer["limit_interval"] = site_info.limit_interval
            indexer["limit_count"] = site_info.limit_count
            indexer["limit_seconds"] = site_info.limit_seconds
            indexer["is_active"] = site_info.is_active
        # 流控器
        interval = int(indexer.get("limit_interval") or 0)
        count = int(indexer.get("limit_count") or 0)
        seconds = int(indexer.get("limit_seconds") or 0)
        domain = StringUtils.get_url_domain(indexer.get("domain") or "")
        if domain and (interval or count or seconds):
            self._ratelimiters[domain] = SiteRateLimiter(interval, count, seconds)
        return indexer

    # ---------- 站点流控 ----------

    def check(self, domain: str) -> Tuple[bool, str]:
        """
        检查站点流控
        """
        limiter = self._ratelimiters.get(domain)
        if not limiter:
            site_info = SiteOper().get_by_domain(domain)
            if site_info:
                limiter = SiteRateLimiter(
                    int(site_info.limit_interval or 0),
                    int(site_info.limit_count or 0),
                    int(site_info.limit_seconds or 0),
                )
                self._ratelimiters[domain] = limiter
        if limiter:
            return limiter.check_rate_limit()
        return False, ""

    # ---------- 用户认证 ----------

    def check_user(self, site: Optional[str] = None,
                   params: Optional[dict] = None) -> Tuple[bool, str]:
        """
        验证用户，外部调用入口

        :param site: 认证站点 ID
        :param params: 认证参数
        :return: 是否认证成功及错误信息
        """
        site = site or ""
        params = params or {}
        if not site:
            from app.core.config import SystemConfigKey, SystemConfigOper
            auth_conf = SystemConfigOper().get(SystemConfigKey.UserSiteAuthParams)
            if auth_conf:
                site = auth_conf.get("site") or ""
                params = auth_conf.get("params") or {}
        siteconf = self._authsites.get(site)
        if not siteconf:
            return False, f"未找到认证站点：{site}"
        handle = _SiteAuthHandle(self._authsites)
        try:
            if site == "sunny":
                status, msg = handle.__sunnypt_auth(siteconf, params)
            elif site == "yemapt":
                status, msg = handle.__yemapt_auth(siteconf, params)
            else:
                status, msg = handle.__nexusphp_auth(siteconf, params)
        except Exception as err:
            logger.error(f"{site}认证出错：{err}")
            return False, str(err)
        if status:
            self._auth_level = 99
            logger.info(f"{site} 认证成功")
        return status, msg


# ============================================================
# 认证站点配置数据（还原自闭源版 .so 内置数据，v2.4.9）
# ============================================================

_AUTHSITES_DATA: Dict[str, dict] = {
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
