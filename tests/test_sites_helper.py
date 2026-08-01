from types import SimpleNamespace

from app.helper.sites import SitesHelper
from app.modules.indexer.spider import SiteSpider


def test_merge_site_conf_uses_complete_site_url_for_search():
    """合并数据库站点后应保留可直接请求的完整基础地址"""
    helper = object.__new__(SitesHelper)
    helper._ratelimiters = {}
    site_info = SimpleNamespace(
        id=2,
        name="测试站点",
        domain="example.com",
        url="https://pt.example.com/",
        cookie="cookie=value",
        ua="test-agent",
        apikey=None,
        token=None,
        proxy=0,
        pri=0,
        downloader="",
        rss="",
        filter=None,
        render=0,
        timeout=15,
        public=0,
        limit_interval=0,
        limit_count=0,
        limit_seconds=0,
        is_active=True,
    )
    indexer = helper._merge_site_conf(
        {
            "id": "example",
            "name": "资源站点",
            "domain": "https://resource.example.com/",
            "search": {
                "paths": [{"path": "torrents.php"}],
                "params": {"search": "{keyword}"},
            },
            "torrents": {"list": {}, "fields": {}},
        },
        site_info,
    )

    assert indexer["domain"] == "https://pt.example.com/"
    assert indexer["url"] == "https://pt.example.com/"
    spider = SiteSpider(indexer=indexer, keyword="movie")
    search_url = spider._SiteSpider__get_search_url()
    assert search_url.startswith("https://pt.example.com/torrents.php?")
