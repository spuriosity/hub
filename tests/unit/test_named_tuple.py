import pytest

from scripts.named_tuple import get_named_city


def test_city_tuple_has_fields():
    city = get_named_city('Montreal', 'Canada')

    assert city.name == 'Montreal'
    assert city.country == 'Canada'
