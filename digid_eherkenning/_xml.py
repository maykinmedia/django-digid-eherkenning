"""
XML parsing with DTD/Entities blocking.

Inspired by https://github.com/mvantellingen/python-zeep/pull/1179/ as their solution
for the deprecated defusedxml.lxml module and the defaults applied in defusedxml.lxml.
"""

from lxml.etree import XMLParser, parse as _parse


def parse(source):
    """
    Parse an LXML etree from source without resolving entities.

    Resolving entities is a security risk, which is why we disable it.
    """
    parser = XMLParser(resolve_entities=False)
    return _parse(source, parser)
