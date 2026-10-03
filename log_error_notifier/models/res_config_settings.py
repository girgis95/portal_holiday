# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.tools import config


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    log_error_min_level = fields.Selection(
        [('WARNING', 'Warning'), ('ERROR', 'Error'), ('CRITICAL', 'Critical')],
        string='Capture Level', default='ERROR',
        config_parameter='log_error_notifier.min_level')
    log_error_scope = fields.Selection([
        ('db', 'This database only'),
        ('db_server', 'This database + server-level messages'),
        ('all', 'All databases on this server'),
    ], string='Scope', default='db_server', config_parameter='log_error_notifier.scope')
    log_error_cooldown_minutes = fields.Integer(
        string='Cooldown (minutes)',
        config_parameter='log_error_notifier.cooldown_minutes')
    log_error_excluded_loggers = fields.Char(
        string='Excluded Loggers', config_parameter='log_error_notifier.excluded_loggers')
    log_error_max_kb_per_run = fields.Integer(
        string='Max KB Read per Run', default=2048,
        config_parameter='log_error_notifier.max_kb_per_run')
    log_error_retention_days = fields.Integer(
        string='Keep Events (days)', help="0 keeps events forever.",
        config_parameter='log_error_notifier.retention_days')
    log_error_logfile = fields.Char(string='Log File', compute='_compute_log_error_logfile')

    @api.depends('company_id')
    def _compute_log_error_logfile(self):
        for settings in self:
            settings.log_error_logfile = config.get('logfile') or False
