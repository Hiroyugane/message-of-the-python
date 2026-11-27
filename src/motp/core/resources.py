"""Read a data file of the package through its loader, without ``pkgutil``.

``pkgutil.get_data`` imports ``importlib.util`` for the same result; the login path avoids
that cost. The loader of the ``motp`` package serves both an unpacked tree
(``SourceFileLoader``) and the archive (``zipimporter``), so catalogues and fonts load from
either (4.6).
"""

import os
from typing import Optional

import motp


def read(name: str) -> Optional[bytes]:
    """The bytes of ``name`` (a ``/``-separated path inside the package), or ``None``.

    Raises ``OSError`` when the loader finds no such file, like ``pkgutil.get_data``.
    """
    get_data = getattr(getattr(motp, "__loader__", None), "get_data", None)
    file = getattr(motp, "__file__", None)
    if get_data is None or file is None:
        return None
    data = get_data(os.path.join(os.path.dirname(file), *name.split("/")))
    return data if isinstance(data, bytes) else None
