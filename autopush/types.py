"""Common types"""
from boto.dynamodb2.items import Item
from typing import (
    Any,
    Dict,
    Union
)


# no mypy reucrsive types yet:
# https://github.com/python/mypy/issues/731
JSONDict = Dict[str, Any]

ItemLike = Union[Item, Dict[str, Any]]
