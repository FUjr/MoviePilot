"""
验证源码站点模块与 V3 查询、认证和流控契约，所有 I/O 均在边界替换。
"""

import importlib.util
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from app.application.site.query import SiteQueryService
from app.schemas.site import Site
from app.schemas.types import SystemConfigKey

MODULE_PATH = Path(__file__).resolve().parents[1] / "app/application/site/sites.py"


@pytest.fixture
def sites_module(monkeypatch):
    """
    单独加载真实实现，不替换全局测试引导中的站点资源替身。
    """
    spec = importlib.util.spec_from_file_location("_moviepilot_sites_under_test", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "get_runtime_setting", lambda key: "test-agent" if key == "USER_AGENT" else "")
    return module


@pytest.fixture
def helper(sites_module, monkeypatch):
    """
    每例使用独立实例和查询替身，不向单例缓存写入状态。
    """
    instance = object.__new__(sites_module.SitesHelper)
    instance.__init__()
    query = Mock(spec=SiteQueryService)
    query.list_ordered_sync.return_value = []
    query.list_ordered = AsyncMock(return_value=[])
    monkeypatch.setattr(sites_module, "get_configured_site_query_service", lambda: query)
    return instance, query


def example_resource(**updates):
    """
    构造带备用域名和 V3 扩展字段的测试站点规则。
    """
    return {
        "id": "example", "name": "资源站点", "domain": "https://resource.example.com/",
        "ext_domains": ["https://backup.example.net/"], "api_domain": "api.example.com",
        "category": {"music": [{"id": 408, "cat": "Music", "param": "cat408"}]},
        "search": {"paths": [{"path": "torrents.php"}], "params": {"search": "{keyword}"}},
        "torrents": {"list": {}, "fields": {}}, **updates,
    }


def example_site(**updates):
    """
    构造脱离数据库会话的站点 DTO。
    """
    return Site.model_validate({
        "id": 2, "name": "测试站点", "domain": "example.com", "url": "https://pt.example.com/",
        "cookie": "cookie=value", "ua": "test-agent", "pri": 1,
        "limit_interval": 60, "limit_count": 2, "limit_seconds": None, **updates,
    })


def test_v3_catalog_preserves_new_sites_and_fields(helper):
    """
    V3 资源包含新增站点、音乐分类和额外接口地址，并保持明文源数据一致。
    """
    instance, _ = helper
    data = json.loads(MODULE_PATH.with_name("user.sites.v3.json").read_text(encoding="utf-8"))
    assert instance.indexer_version == "3.0.25"
    assert len(data["indexers"]) == 183
    assert {"colapt", "oldtoons", "speedapp", "vclib", "xdypt"} <= data["indexers"].keys()
    conf = instance.get_indexer("www.colapt.com")
    assert conf["api_domain"] == "api.colapt.com"
    assert instance.get_indexer("haidan.cc")["category"]["music"]
    assert instance.auth_level == 99


def test_merge_site_conf_uses_complete_site_url_for_search(helper):
    """
    合并站点后爬虫使用完整 URL，保留登录凭据及 V3 扩展字段。
    """
    from app.modules.indexer.spider import SiteSpider

    instance, query = helper
    instance.add_indexer(example_resource())
    query.list_ordered_sync.return_value = [example_site()]
    indexer = instance.get_indexers()[0]
    assert indexer["domain"] == "https://pt.example.com/"
    assert indexer["url"] == "https://pt.example.com/"
    assert indexer["id"] == 2
    assert indexer["cookie"] == "cookie=value"
    assert indexer["api_domain"] == "api.example.com"
    assert indexer["category"]["music"][0]["param"] == "cat408"
    spider = SiteSpider(indexer=indexer, keyword="movie")
    assert spider._SiteSpider__get_search_url().startswith("https://pt.example.com/torrents.php?")


def test_only_configured_active_sites_are_searchable_and_order_is_preserved(helper):
    """
    内置清单不等于已配置站点，搜索列表只投影启用站点并保留查询顺序。
    """
    instance, query = helper
    instance.add_indexer(example_resource())
    instance.add_indexer(example_resource(id="second", domain="https://second.org/", ext_domains=[]))
    query.list_ordered_sync.return_value = [
        example_site(id=3, domain="second.org", url="https://second.org/", pri=0),
        example_site(), example_site(id=4, is_active=False), example_site(id=5, domain="unknown.org"),
    ]
    assert [item["id"] for item in instance.get_indexers()] == [3, 2]
    query.list_ordered_sync.assert_called_once_with()


@pytest.mark.asyncio
async def test_async_queries_do_not_call_sync_repository(helper):
    """
    异步列表及单站点查询只等待异步服务；备用域名匹配同一配置。
    """
    instance, query = helper
    instance.add_indexer(example_resource())
    query.list_ordered.return_value = [example_site(is_active=False)]
    assert await instance.async_get_indexers() == []
    indexer = await instance.async_get_indexer("https://backup.example.net/torrents.php")
    assert indexer["id"] == 2
    assert indexer["is_active"] is False
    query.list_ordered_sync.assert_not_called()
    assert query.list_ordered.await_count == 2


def test_add_indexer_replaces_aliases_and_returns_independent_copies(helper):
    """
    动态规则更新移除旧别名，输入及查询结果的修改不污染内部资源。
    """
    instance, _ = helper
    resource = example_resource()
    instance.add_indexer(resource)
    resource["category"].clear()
    assert instance.get_indexer("example.net")["category"]["music"]
    result = instance.get_indexsites()
    result["example.net"]["id"] = "changed"
    assert instance.get_indexsites()["example.net"]["id"] == "example"
    instance.add_indexer(example_resource(domain="https://replacement.org/", ext_domains=[]))
    assert instance.get_indexer("example.net") is None
    assert instance.get_indexer("replacement.org")["id"] == "example"
    forms = instance.get_authsites()
    forms["haidan"]["params"].clear()
    assert instance.get_authsites()["haidan"]["params"]


def test_query_refresh_and_aliases_share_rate_limit_history(helper, sites_module, monkeypatch):
    """
    重复查询及不同别名不能重置次数限制，配置变化才重建状态。
    """
    instance, query = helper
    instance.add_indexer(example_resource())
    query.list_ordered_sync.return_value = [example_site(limit_count=1)]
    monkeypatch.setattr(sites_module.time, "monotonic", lambda: 100.0)
    instance.get_indexers()
    assert instance.check("https://pt.example.com/") == (False, "")
    instance.get_indexers()
    query.list_ordered_sync.reset_mock()
    assert instance.check("backup.example.net")[0] is True
    query.list_ordered_sync.assert_not_called()
    query.list_ordered_sync.return_value = [example_site(limit_count=2)]
    instance.get_indexers()
    assert instance.check("example.net") == (False, "")
    query.list_ordered_sync.return_value = [example_site(limit_count=None, limit_interval=None)]
    instance.get_indexers()
    assert instance.check("example.com") == (False, "")


def test_replaced_alias_does_not_reuse_old_rate_limit(helper, sites_module, monkeypatch):
    """
    动态规则删除的备用域名不再沿用原站点的限流映射。
    """
    instance, query = helper
    instance.add_indexer(example_resource())
    query.list_ordered_sync.return_value = [example_site(limit_count=1)]
    monkeypatch.setattr(sites_module.time, "monotonic", lambda: 100.0)
    instance.get_indexers()
    assert instance.check("example.com") == (False, "")
    assert instance.check("example.net")[0] is True
    instance.add_indexer(example_resource(ext_domains=[]))
    assert instance.check("example.net") == (False, "")
    assert instance.check("example.com")[0] is True


def test_rate_limit_fixed_window_and_rejected_attempts(sites_module, monkeypatch):
    """
    窗口到期按首次接受请求计时，拒绝尝试不延迟恢复。
    """
    now = [0.0]
    monkeypatch.setattr(sites_module.time, "monotonic", lambda: now[0])
    limiter = sites_module.SiteRateLimiter(10, 2, 3)
    assert limiter.check_rate_limit() == (False, "")
    now[0] = 2
    assert limiter.check_rate_limit()[0] is True
    now[0] = 3
    assert limiter.check_rate_limit() == (False, "")
    now[0] = 9
    assert limiter.check_rate_limit()[0] is True
    now[0] = 10
    assert limiter.check_rate_limit() == (False, "")
    unlimited = sites_module.SiteRateLimiter(None, None, None)
    assert all(unlimited.check_rate_limit() == (False, "") for _ in range(10))


def test_concurrent_rate_limit_reservations_are_atomic(sites_module, monkeypatch):
    """
    多线程同时申请额度时，成功次数不得超过窗口配置。
    """
    monkeypatch.setattr(sites_module.time, "monotonic", lambda: 0.0)
    limiter = sites_module.SiteRateLimiter(60, 4, None)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: limiter.check_rate_limit(), range(32)))
    assert sum(not limited for limited, _ in results) == 4


@pytest.mark.parametrize("params", [{"apikey": "test-key"}, {"SUNNY_APIKEY": "test-key"},
                                     {"apikey": "old-key", "SUNNY_APIKEY": "test-key"}])
def test_auth_accepts_v3_prefixed_and_legacy_fields(helper, sites_module, monkeypatch, params):
    """
    V3 前缀字段优先，旧字段仍能分发到真实认证端口。
    """
    instance, _ = helper
    port = Mock()
    port.get_json.return_value = (200, {"success": True, "data": {"can_download": True}})
    monkeypatch.setattr(sites_module, "get_site_auth_http", lambda: port)
    assert instance.check_user("sunny", params) == (True, "认证成功")
    assert port.get_json.call_args.kwargs["headers"]["Authorization"] == "Bearer test-key"


def test_auth_loads_saved_config_and_does_not_expose_secrets(helper, sites_module, monkeypatch):
    """
    默认认证从配置服务读取，传输失败的返回值不得包含私密 URL。
    """
    instance, _ = helper
    config = Mock()
    config.get.return_value = {"site": "haidan", "params": {"HAIDAN_ID": "7", "HAIDAN_PASSKEY": "a&b"}}
    port = Mock()
    port.get_json.side_effect = RuntimeError("https://example.com/?passkey=a&b")
    monkeypatch.setattr(sites_module, "get_configured_system_config", lambda: config)
    monkeypatch.setattr(sites_module, "get_site_auth_http", lambda: port)
    assert instance.check_user() == (False, "站点认证请求失败")
    config.get.assert_called_once_with(SystemConfigKey.UserSiteAuthParams)
    assert "passkey=a%26b" in port.get_json.call_args.kwargs["url"]


def test_auth_environment_overrides_saved_config(helper, sites_module, monkeypatch):
    """
    AUTH_SITE 设置后读取对应环境凭据，不回退到另一站点的持久化参数。
    """
    instance, _ = helper
    monkeypatch.setattr(sites_module, "get_runtime_setting", lambda key: "sunny" if key == "AUTH_SITE" else "test-agent")
    monkeypatch.setenv("SUNNY_APIKEY", "environment-key")
    port = Mock()
    port.get_json.return_value = (403, {})
    monkeypatch.setattr(sites_module, "get_site_auth_http", lambda: port)
    assert instance.check_user()[0] is False
    assert port.get_json.call_args.kwargs["headers"]["Authorization"] == "Bearer environment-key"
