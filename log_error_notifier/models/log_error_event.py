# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import api, fields, models

LEVEL_SELECTION = [
    ('WARNING', 'Warning'),
    ('ERROR', 'Error'),
    ('CRITICAL', 'Critical'),
]


class LogErrorEvent(models.Model):
    _name = 'log.error.event'
    _description = 'Log Error Event'
    _order = 'last_seen desc, id desc'

    name = fields.Char(string='Summary', required=True, readonly=True)
    fingerprint = fields.Char(required=True, readonly=True, index=True)
    level = fields.Selection(LEVEL_SELECTION, required=True, readonly=True)
    logger_name = fields.Char(string='Logger', readonly=True)
    db_name = fields.Char(string='Database', readonly=True)
    host = fields.Char(readonly=True)
    first_seen = fields.Datetime(readonly=True)
    last_seen = fields.Datetime(readonly=True, index=True)
    last_log_time = fields.Char(string='Last Log Timestamp', readonly=True,
                                help="Raw timestamp from the log file (server local time).")
    occurrence_count = fields.Integer(string='Occurrences', readonly=True)
    pending_count = fields.Integer(string='Pending Notification', readonly=True,
                                   help="Occurrences not yet notified.")
    last_notified = fields.Datetime(readonly=True)
    sample = fields.Text(string='Last Traceback', readonly=True,
                         help="Redacted and truncated copy of the last occurrence.")
    muted = fields.Boolean(help="Keep counting this error but never notify about it.")

    _sql_constraints = [
        ('fingerprint_uniq', 'unique(fingerprint)', 'An event with this fingerprint already exists.'),
    ]

    def action_mute(self):
        self.write({'muted': True, 'pending_count': 0})

    def action_unmute(self):
        self.write({'muted': False})

    @api.autovacuum
    def _gc_old_events(self):
        days = int(self.env['ir.config_parameter'].sudo().get_param('log_error_notifier.retention_days', 0) or 0)  # 0/missing: keep forever
        if days > 0:
            limit_date = fields.Datetime.now() - timedelta(days=days)
            self.search([('last_seen', '<', limit_date)]).unlink()
