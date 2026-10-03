# -*- coding: utf-8 -*-
import json
import os
import tempfile
from unittest.mock import patch

from odoo.exceptions import ValidationError
from odoo.tests import TransactionCase, tagged

from ..tools import log_parser

LOG = """\
2026-10-02 10:00:00,001 4242 INFO db1 odoo.modules.loading: loading 1 modules...
2026-10-02 10:00:01,002 4242 ERROR db1 odoo.http: Exception during request handling.
Traceback (most recent call last):
  File "/odoo/http.py", line 10, in dispatch
    raise ValueError("bad id 42")  # password=hunter2
ValueError: bad id 42
2026-10-02 10:00:02,003 4242 WARNING ? odoo.service.server: slow request
2026-10-02 10:00:03,004 4242 ERROR db2 odoo.http: Exception during request handling.
Traceback (most recent call last):
ValueError: bad id 77
"""


@tagged('post_install', '-at_install')
class TestLogParser(TransactionCase):

    def test_parse_entries(self):
        entries = list(log_parser.iter_entries(LOG.splitlines(), log_parser.LEVELS['WARNING']))
        self.assertEqual([e.level for e in entries], ['ERROR', 'WARNING', 'ERROR'])
        self.assertEqual(entries[0].db, 'db1')
        self.assertEqual(entries[0].exception_line, 'ValueError: bad id 42')
        # same error with different numbers / databases shares a fingerprint
        self.assertEqual(entries[0].fingerprint, entries[2].fingerprint)

    def test_redaction(self):
        text = log_parser.redact(
            "password=hunter2 {'api_key': 'abc'} Authorization: Bearer eyJabc.def "
            "postgresql://odoo:s3cret@db:5432/x")
        for secret in ('hunter2', 'abc', 'eyJabc', 's3cret'):
            self.assertNotIn(secret, text)
        for leak in ("db_password=hunter2", "{'smtp_password': 'hunter2 with spaces'}", "password=b'hunter2'",
                     "[('password', '=', 'hunter2')]", "redis://:hunter2@h",
                     "-----BEGIN RSA PRIVATE KEY-----\nhunter2\n-----END RSA PRIVATE KEY-----"):
            self.assertNotIn('hunter2', log_parser.redact(leak))
        for normal in ("Basic authentication failed", "A bearer of bad news"):
            self.assertEqual(log_parser.redact(normal), normal)

    def test_long_record_keeps_exception_line(self):
        lines = ["2026-10-02 10:00:01,002 1 ERROR d odoo.x: boom", "Traceback (most recent call last):"] \
            + ["  frame %d" % i for i in range(log_parser.MAX_DETAIL_LINES + 50)] + ["KeyError: 'k'"]
        entry = next(log_parser.iter_entries(lines))
        self.assertEqual(entry.exception_line, "KeyError: 'k'")
        self.assertTrue(entry.truncated)

    def test_incremental_read_and_rotation(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.log') as f:
            f.write(LOG)
        try:
            # first run starts at end of file
            res = log_parser.read_new_lines(f.name, 0, 0, 1 << 20, 1 << 24)
            self.assertFalse(res.lines)
            with open(f.name, 'a') as f2:
                f2.write(LOG)
            res2 = log_parser.read_new_lines(f.name, res.inode, res.offset, 1 << 20, 1 << 24)
            self.assertEqual(len(res2.lines), len(LOG.splitlines()))
            # truncated file (copytruncate rotation) restarts at 0
            with open(f.name, 'w') as f3:
                f3.write(LOG[:200])
            res3 = log_parser.read_new_lines(f.name, res2.inode, res2.offset, 1 << 20, 1 << 24)
            self.assertEqual(res3.offset, LOG[:200].rfind('\n') + 1)
            # small chunk never splits a traceback from its header
            res4 = log_parser.read_new_lines(f.name, res.inode, 0, 150, 1 << 24)
            self.assertTrue(all(not l.startswith(('Traceback', ' ')) for l in res4.lines[:1]))
        finally:
            os.unlink(f.name)


@tagged('post_install', '-at_install')
class TestLogErrorNotifier(TransactionCase):

    def test_webhook_validation(self):
        Channel = self.env['log.error.channel']
        for url in ('http://x.webhook.office.com/a', 'https://evil.com/x',
                    'https://webhook.office.com.evil.com/x', 'https://u:p@x.webhook.office.com/a',
                    'https://127.0.0.1\\.webhook.office.com/a', 'https://evil.com#@x.webhook.office.com/'):
            with self.assertRaises(ValidationError):
                Channel.create({'name': 't', 'channel_type': 'teams', 'webhook_url': url})
        Channel.create({'name': 't', 'channel_type': 'teams',
                        'webhook_url': 'https://prod-01.westeurope.logic.azure.com/workflows/x'})

    def test_scan_dedup_and_notify(self):
        dbname = self.env.cr.dbname
        log = LOG.replace('db1', dbname)
        self.env['ir.config_parameter'].set_param('log_error_notifier.scope', 'db_server')
        self.env['log.error.channel'].create({'name': 'IT', 'channel_type': 'email', 'email_to': 'it@example.com'})
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.log') as f:
            pass
        scanner = self.env['log.error.scanner']
        try:
            with patch.object(type(scanner), '_get_log_path', lambda self: f.name):
                scanner._cron_scan_log()  # initialise at EOF
                with open(f.name, 'a') as fa:
                    fa.write(log + log)
                scanner._cron_scan_log()
        finally:
            os.unlink(f.name)
        event = self.env['log.error.event'].search([('logger_name', '=', 'odoo.http')])
        self.assertEqual(len(event), 1, "db2 entries are out of scope, db1 ones are grouped")
        self.assertEqual(event.occurrence_count, 2)
        self.assertEqual(event.pending_count, 0, "notified")
        self.assertNotIn('hunter2', event.sample)
        mail = self.env['mail.mail'].search([('email_to', '=', 'it@example.com')])
        self.assertEqual(len(mail), 1)
        self.assertNotIn('hunter2', mail.body_html)

    def test_teams_payload_size(self):
        items = [{'level': 'ERROR', 'count': 1, 'logger': 'x', 'summary': 's' * 200,
                  'traceback': 't' * 4000, 'url': False}] * 30
        payload = self.env['log.error.channel']._teams_payload(items, {
            'title': 't', 'db_name': 'd', 'host': 'h', 'url': False})
        self.assertLess(len(payload.encode()), 25001)
        self.assertEqual(json.loads(payload)['type'], 'message')
