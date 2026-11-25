"""Identity of the editor text used for compilation and repair."""
from contextvars import ContextVar
import hashlib
import unicodedata

active_file = ContextVar("active_file", default="")


def normalize_source(source):
    # Preserve danda in the diagnostic input so the lexer can report its location.
    return unicodedata.normalize("NFC", source.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n"))


def source_hash(source):
    return hashlib.sha256(normalize_source(source).encode("utf-8")).hexdigest()


def cache_identity(source, language, version):
    return (active_file.get(), language.casefold(), source_hash(source), version)
