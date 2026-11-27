"""Core contracts: data model, sanitiser, thresholds, probe documents, cache, messages, hints.

Everything in this package is pure logic. The one exception is ``cache.read_cache_file``,
which opens a single file with the restrictions of blueprint section 4.4.
"""
