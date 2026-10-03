# -*- coding: utf-8 -*-
"""Pure-python helpers (no Odoo imports) to tail and parse the Odoo log file.

Odoo log line format (odoo/netsvc.py):
    %(asctime)s %(pid)s %(levelname)s %(dbname)s %(name)s: %(message)s %(perf_info)s
Traceback lines follow the header line and do not start with a timestamp.
"""
import hashlib
import os
import re
import stat
from collections import deque
from dataclasses import dataclass, field

LEVELS = {'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}

HEADER_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (?P<pid>\d+) '
    r'(?P<level>[A-Z]+) (?P<db>\S+) (?P<logger>[^\s:]+): (?P<msg>.*)$'
)
# Start of a log record inside a raw chunk, used to avoid splitting a traceback
HEADER_START_RE = re.compile(rb'\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \d+ ')

MAX_DETAIL_LINES = 300
MAX_TEXT_LENGTH = 20000

# matches db_password, admin_passwd, smtp_pass, secret_key, access_token, ...
_SECRET_KEY = (
    r'\w*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|authorization|session_id|cookie|smtp_pass)\w*'
)
# a quoted value (optionally bytes b'...') up to its closing quote, or a bare word
# (both patterns below have exactly one group before it, hence \3)
_SECRET_VALUE = r'''(?:(b?)(['"])(?:(?!\3).)*\3|(?:[Bb]earer|[Bb]asic)\s+[^\s"',;]+|[^\s"',;&)}\]]+)'''

_REDACT_PATTERNS = [
    # PEM private keys
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', re.S),
     '-----BEGIN PRIVATE KEY----- *** -----END PRIVATE KEY-----'),
    # Authorization schemes first so "authorization: Bearer xyz" is fully masked.
    # The credential must contain a digit or base64 symbol: "Basic authentication" is kept.
    (re.compile(r'\b([Bb]earer|[Bb]asic)\s+(?=[A-Za-z\-._~]*[0-9+/=])[A-Za-z0-9\-._~+/]{6,}=*'), r'\1 ***'),
    # ORM domain leaves: ('password', '=', 'value')
    (re.compile(
        r'''(?i)(['"]%s['"]\s*,\s*['"][=!<>a-z ]+['"]\s*,\s*)%s''' % (_SECRET_KEY, _SECRET_VALUE)
    ), r'\1\2\3***\3'),
    # key=value / key: value / 'key': 'value' / key=b'value'
    (re.compile(
        r'''(?i)(?<![A-Za-z0-9])(%s['"]?\s*[:=]\s*)%s''' % (_SECRET_KEY, _SECRET_VALUE)
    ), r'\1\2\3***\3'),
    # credentials embedded in URLs / DSNs: scheme://user:pass@host (user may be empty)
    (re.compile(r'(\w+://)[^/\s:@]*:[^\s@/?#]*@'), r'\1***:***@'),
]

_NORMALIZE_PATTERNS = [
    (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '<uuid>'),
    (re.compile(r'0x[0-9a-fA-F]+'), '<hex>'),
    (re.compile(r'\d+'), '<n>'),
]


@dataclass
class LogEntry:
    timestamp: str
    level: str
    db: str
    logger: str
    message: str
    details: deque = field(default_factory=lambda: deque(maxlen=MAX_DETAIL_LINES))
    truncated: bool = False
    last_unindented: str = ''

    @property
    def text(self):
        head = [self.message, '[... truncated ...]'] if self.truncated else [self.message]
        return '\n'.join(head + list(self.details))[-MAX_TEXT_LENGTH:]

    @property
    def exception_line(self):
        """Last unindented traceback line, e.g. ``ValueError: bad value``."""
        return self.last_unindented

    @property
    def summary(self):
        exc = self.exception_line
        summary = '%s (%s)' % (self.message.strip(), exc) if exc else self.message.strip()
        return redact(summary)[:250] or self.logger

    @property
    def fingerprint(self):
        key = '|'.join([self.level, self.logger, normalize(self.message[:500]), normalize(self.exception_line[:500])])
        return hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:40]


@dataclass
class ReadResult:
    lines: list
    inode: int
    offset: int
    skipped_bytes: int = 0


def redact(text):
    for pattern, repl in _REDACT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def normalize(text):
    for pattern, repl in _NORMALIZE_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def read_new_lines(path, inode, offset, max_bytes, max_backlog):
    """Read complete lines appended to ``path`` since ``offset``.

    * first run (inode is falsy): start at end of file, don't replay history
    * rotation/truncation (inode changed or file shrank): restart at 0
    * backlog > max_backlog: jump ahead to keep each run bounded
    * never returns a partial line, and avoids cutting a traceback in two
      when the chunk is limited by ``max_bytes``
    """
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError('%s is not a regular file' % path)
    size = st.st_size
    if not inode:
        return ReadResult([], st.st_ino, size)
    if st.st_ino != inode or size < offset:
        offset = 0

    skipped = 0
    if size - offset > max_backlog:
        skipped = size - max_bytes - offset
        offset = size - max_bytes
    if size <= offset:
        return ReadResult([], st.st_ino, offset)

    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read(max_bytes)

    start = 0
    if skipped:
        # we jumped in the middle of a record: resume at the next record header
        first_header = HEADER_START_RE.search(data)
        start = first_header.start() + 1 if first_header else 0
        if not start:
            return ReadResult([], st.st_ino, offset + len(data), skipped + len(data))
    end = data.rfind(b'\n') + 1
    if end <= start:
        if len(data) >= max_bytes:
            # a single line bigger than max_bytes: skip it rather than stall
            return ReadResult([], st.st_ino, offset + len(data), skipped + len(data))
        return ReadResult([], st.st_ino, offset, skipped)
    if len(data) >= max_bytes:
        last_header = None
        for last_header in HEADER_START_RE.finditer(data, start, end):
            pass
        if last_header and last_header.start() + 1 > start:
            end = last_header.start() + 1

    chunk = data[start:end].decode('utf-8', 'replace')
    # split on '\n' only: splitlines() also breaks on \x0c, U+2028, ... which
    # would let logged user input forge a header line
    lines = [line.rstrip('\r') for line in chunk.split('\n')[:-1]]
    return ReadResult(lines, st.st_ino, offset + end, skipped + start)


def iter_entries(lines, min_level=LEVELS['ERROR']):
    """Group lines into LogEntry objects, keeping only levels >= min_level."""
    current = None
    for line in lines:
        match = HEADER_RE.match(line)
        if match:
            if current is not None:
                yield current
            current = None
            if LEVELS.get(match['level'], 0) >= min_level:
                current = LogEntry(
                    timestamp=match['ts'], level=match['level'], db=match['db'],
                    logger=match['logger'], message=match['msg'],
                )
        elif current is not None:
            # keep the tail: the final exception line matters more than the head
            current.truncated |= len(current.details) == MAX_DETAIL_LINES
            current.details.append(line)
            if line.strip() and not line[0].isspace():
                current.last_unindented = line.strip()
    if current is not None:
        yield current
