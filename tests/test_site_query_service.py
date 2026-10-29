"""
站点查询应用服务的稳定快照投影契约测试。
"""

from unittest.mock import Mock

from app.application.site.contract import SiteSnapshot, SiteUserDataSnapshot
from app.application.site.query import SiteQueryService
from app.schemas.site import Site, SiteUserData


def test_list_ordered_sync_projects_snapshots_without_changing_order() -> None:
    """
    同步兼容查询只投影仓储快照，保留仓储优先级顺序和可空流控参数。
    """
    repository = Mock()
    repository.list_order_by_pri.return_value = [
        SiteSnapshot(id=9, name="优先站点", url="https://first.test/", pri=0),
        SiteSnapshot(id=2, name="后续站点", url="https://second.test/", pri=1),
    ]

    result = SiteQueryService(repository).list_ordered_sync()

    assert all(isinstance(site, Site) for site in result)
    assert [site.id for site in result] == [9, 2]
    assert result[0].limit_interval is None
    repository.list_order_by_pri.assert_called_once_with()


def test_userdata_latest_sync_projects_snapshot_to_dto() -> None:
    """
    同步站点用户数据查询只消费脱离 Session 的稳定快照。
    """
    record = SiteUserDataSnapshot(
        id=1,
        domain="site.example",
        name="示例站点",
        username="tester",
        userid="42",
        user_level="Power User",
        upload=1024.0,
        download=512.0,
        seeding=3.0,
        leeching=1.0,
        seeding_size=2048.0,
        leeching_size=256.0,
    )
    repository = Mock()
    repository.get_userdata_latest.return_value = [record]

    result = SiteQueryService(repository).userdata_latest_sync()

    assert isinstance(result[0], SiteUserData)
    assert result[0].domain == "site.example"
    assert result[0].name == "示例站点"
    assert result[0].userid == "42"
    assert result[0].upload == 1024
