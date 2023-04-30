from collections import defaultdict
from typing import Iterator, Dict


def group_by(cve_datas, selector):
    assert callable(selector)
    result = defaultdict(list)
    for cve_data in cve_datas:
        result[selector(cve_data)].append(cve_data)
    return result


def select(cve_datas, key):
    assert callable(key)
    return [cve_data for cve_data in cve_datas if key(cve_data)]


def first_of(*items):
    for item in items:
        if len(item) > 0:
            assert len(item) == 1
            return item[0]
    raise f"all of items are empty: {items}"


def resolve_nested_dict(dict_data, keys) -> str | None:
    if len(keys) == 0:
        return None
    key = keys[0]
    if key not in dict_data:
        return None
    if len(keys) == 1:
        return dict_data[key]
    return resolve_nested_dict(dict_data[key], keys[1:])


def iter_nested_dict(dict_data, keys) -> Iterator[Dict]:
    """
    e.g.
    "a": [
        {
            "b": [
                {
                    "target_key": "value"
                },
                ...
            ]
        },
        {
            "b": [
                {
                    "target_key": "value"
                },
                ...
            ]
        },
    ]

    iter_nested_dict(json_data, ["a", "b"])
    would iter through all the dicts:
    {
        "target_key": "value"
    }
    """
    if isinstance(dict_data, list):
        for item in dict_data:
            yield from iter_nested_dict(item, keys)
        return

    if len(keys) == 0:
        return
    key, rest_keys = keys[0], keys[1:]
    if key not in dict_data:
        return
    res = dict_data[key]
    if len(rest_keys) == 0:
        if isinstance(res, list):
            yield from res
        else:
            yield res
    else:
        yield from iter_nested_dict(res, rest_keys)
