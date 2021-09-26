from collections import namedtuple

import pytest


def get_named_city(name, country, population=None, zip=None):
    City = namedtuple('City', 'name country population zip')

    this_city = City(name=name, country=country, population=population, zip=zip)

    return this_city

