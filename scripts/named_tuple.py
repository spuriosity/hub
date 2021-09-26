from collections import namedtuple

import pytest

def get_named_city(name, country):
    City = namedtuple('City', 'name country population zip')

    this_city = City(name=name, country=country)

    return this_city

