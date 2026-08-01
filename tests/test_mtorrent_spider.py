import httpx

from app.core.config import settings
from app.modules.indexer.spider.mtorrent import MTorrentSpider


def test_decode_json_response_replaces_invalid_utf8_bytes():
    """MTorrent JSON 中的非法 UTF-8 字节不应导致整次搜索失败"""
    response = httpx.Response(
        status_code=200,
        content=b'\xef\xbb\xbf{"data":{"data":[{"name":"bad \xbc title"}]}}',
    )

    payload = MTorrentSpider._decode_json_response(response)

    assert payload["data"]["data"][0]["name"] == "bad \ufffd title"


def test_decode_json_response_keeps_valid_utf8_content():
    """合法 UTF-8 JSON 应继续使用响应对象的标准解析路径"""
    response = httpx.Response(
        status_code=200,
        content='{"data":{"data":[{"name":"测试标题"}]}}'.encode("utf-8"),
    )

    payload = MTorrentSpider._decode_json_response(response)

    assert payload["data"]["data"][0]["name"] == "测试标题"


def test_empty_user_agent_uses_global_default():
    """站点未配置 UA 时应使用全局默认值，避免 API 返回登录页面"""
    spider = MTorrentSpider(
        {
            "id": 1,
            "name": "测试站点",
            "domain": "https://example.com/",
            "ua": "",
        }
    )

    assert spider._ua == settings.USER_AGENT
