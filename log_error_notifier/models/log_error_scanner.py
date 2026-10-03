# -*- coding: utf-8 -*-
import logging
import os
import socket
from collections import OrderedDict
from datetime import timedelta

from odoo import _, api, fields, models
from odoo.tools import config

from ..tools.log_parser import LEVELS, iter_entries, read_new_lines, redact

_logger = logging.getLogger(__name__)

# never report our own messages: avoids a feedback loop on delivery failures
OWN_LOGGER = 'odoo.addons.log_error_notifier'
MAX_EVENTS_PER_DIGEST = 30
EMAIL_TRACEBACK_CHARS = 4000


class LogErrorScanState(models.Model):
    """Read position in the log file, per host (one DB may be served by
    several hosts, each with its own log file). Kept out of
    ir.config_parameter on purpose: writing parameters clears the registry
    caches of every worker."""
    _name = 'log.error.scan.state'
    _description = 'Log Error Scan State'

    host = fields.Char(required=True)
    path = fields.Char(required=True)
    # Char: inode / offset can exceed the int4 range of fields.Integer
    inode = fields.Char()
    offset = fields.Char()
    last_scan = fields.Datetime()

    _sql_constraints = [
        ('host_path_uniq', 'unique(host, path)', 'One scan state per host and log file.'),
    ]


class LogErrorScanner(models.AbstractModel):
    _name = 'log.error.scanner'
    _description = 'Log Error Scanner'

    @api.model
    def _get_params(self):
        get = self.env['ir.config_parameter'].sudo().get_param

        def get_int(key, default):
            try:
                return int(get(key, default))
            except (TypeError, ValueError):
                return default

        excluded = [l.strip() for l in (get('log_error_notifier.excluded_loggers') or '').split(',') if l.strip()]
        max_bytes = max(64, get_int('log_error_notifier.max_kb_per_run', 2048)) * 1024
        return {
            'min_level': LEVELS.get(get('log_error_notifier.min_level', 'ERROR'), LEVELS['ERROR']),
            # missing parameter == 0: the settings screen deletes parameters set to 0,
            # the initial 60 comes from data/ir_config_parameter.xml
            'cooldown': max(0, get_int('log_error_notifier.cooldown_minutes', 0)),
            'scope': get('log_error_notifier.scope', 'db_server'),
            'excluded_loggers': tuple([OWN_LOGGER] + excluded),
            'max_bytes': max_bytes,
            'max_backlog': max_bytes * 20,
        }

    @api.model
    def _get_log_path(self):
        # Only the server configuration decides which file is read; it is
        # intentionally not editable from the UI (would allow reading any file).
        path = config.get('logfile')
        return os.path.realpath(path) if path else False

    @api.model
    def _context_info(self, title):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url', '')
        return {
            'title': title,
            'db_name': self.env.cr.dbname,
            'host': socket.gethostname(),
            'url': base_url and '%s/odoo/action-log_error_notifier.action_log_error_event' % base_url,
        }

    # ------------------------------------------------------------------
    # Cron
    # ------------------------------------------------------------------

    @api.model
    def _cron_scan_log(self):
        path = self._get_log_path()
        if not path:
            _logger.debug("Log error notifier: no logfile configured, nothing to scan")
            return
        params = self._get_params()
        host = socket.gethostname()
        State = self.env['log.error.scan.state'].sudo()
        state = State.search([('host', '=', host), ('path', '=', path)], limit=1) \
            or State.create({'host': host, 'path': path})
        try:
            result = read_new_lines(path, int(state.inode or 0), int(state.offset or 0),
                                    params['max_bytes'], params['max_backlog'])
        except (OSError, ValueError) as e:
            _logger.warning("Log error notifier: cannot read %s: %s", path, e)
            return
        if result.skipped_bytes:
            _logger.warning("Log error notifier: log backlog too large, skipped %s bytes", result.skipped_bytes)

        entries = [e for e in iter_entries(result.lines, params['min_level']) if self._keep_entry(e, params)]
        self._store_entries(entries, host)
        state.write({'inode': str(result.inode), 'offset': str(result.offset), 'last_scan': fields.Datetime.now()})
        self._notify_pending(params)

    @api.model
    def _keep_entry(self, entry, params):
        if entry.logger.startswith(params['excluded_loggers']):
            return False
        dbname = self.env.cr.dbname
        if params['scope'] == 'db':
            return entry.db == dbname
        if params['scope'] == 'db_server':
            return entry.db in (dbname, '?')
        return True

    @api.model
    def _store_entries(self, entries, host):
        if not entries:
            return
        # aggregate in memory first: one read + one write per distinct error
        groups = OrderedDict()
        for entry in entries:
            group = groups.setdefault(entry.fingerprint, {'count': 0})
            group['count'] += 1
            group['entry'] = entry
        Event = self.env['log.error.event'].sudo()
        existing = {e.fingerprint: e for e in Event.search([('fingerprint', 'in', list(groups))])}
        now = fields.Datetime.now()
        to_create = []
        for fingerprint, group in groups.items():
            entry = group['entry']
            vals = {
                'name': entry.summary,
                'last_seen': now,
                'last_log_time': entry.timestamp,
                'sample': redact(entry.text),
                'host': host,
                'db_name': entry.db,
            }
            event = existing.get(fingerprint)
            if event:
                vals['occurrence_count'] = event.occurrence_count + group['count']
                if not event.muted:
                    vals['pending_count'] = event.pending_count + group['count']
                event.write(vals)
            else:
                to_create.append(dict(
                    vals, fingerprint=fingerprint, level=entry.level, logger_name=entry.logger,
                    first_seen=now, occurrence_count=group['count'], pending_count=group['count'],
                ))
        if to_create:
            Event.create(to_create)

    @api.model
    def _notify_pending(self, params):
        channels = self.env['log.error.channel'].sudo().search([])
        if not channels:
            return
        now = fields.Datetime.now()
        domain = [('pending_count', '>', 0), ('muted', '=', False)]
        if params['cooldown']:
            domain += ['|', ('last_notified', '=', False),
                       ('last_notified', '<', now - timedelta(minutes=params['cooldown']))]
        events = self.env['log.error.event'].sudo().search(domain, order='last_seen desc', limit=MAX_EVENTS_PER_DIGEST)
        if not events:
            return
        events = events.sorted(lambda e: (-LEVELS.get(e.level, 0), -e.pending_count))

        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url', '')
        items = [{
            'level': event.level,
            'count': event.pending_count,
            'logger': event.logger_name or '',
            'summary': event.name,
            'traceback': (event.sample or '')[-EMAIL_TRACEBACK_CHARS:],
            'url': base_url and '%s/odoo/action-log_error_notifier.action_log_error_event/%s' % (base_url, event.id),
        } for event in events]
        total = sum(events.mapped('pending_count'))
        context_info = self._context_info(
            _("[Odoo %(db)s] %(count)s log error(s) - %(levels)s", db=self.env.cr.dbname, count=total,
              levels=', '.join(sorted(set(events.mapped('level'))))))

        results = [channel._send_digest(items, context_info) for channel in channels]
        # a failed channel keeps events pending so the next run retries (channels
        # that already succeeded may then receive them twice, better than never)
        if False not in results:
            events.write({'pending_count': 0, 'last_notified': now})
