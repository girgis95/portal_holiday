# -*- coding: utf-8 -*-
import json
import logging
import re
from urllib.parse import urlparse

import requests
from urllib3.util import parse_url

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError
from odoo.tools import email_normalize, email_split

from .log_error_event import LEVEL_SELECTION
from ..tools.log_parser import LEVELS

_logger = logging.getLogger(__name__)

# Only Microsoft hosts can receive webhooks: prevents using the server as an
# SSRF proxy towards internal services. Legacy O365 connectors use
# *.webhook.office.com, Teams "Workflows" use Logic Apps / Power Platform.
ALLOWED_WEBHOOK_HOST_SUFFIXES = (
    '.webhook.office.com',
    '.logic.azure.com',
    '.powerplatform.com',
)
TEAMS_MAX_PAYLOAD = 25000  # Teams rejects messages above ~28 KB
REQUEST_TIMEOUT = 10


class LogErrorChannel(models.Model):
    _name = 'log.error.channel'
    _description = 'Log Error Notification Channel'
    _order = 'sequence, id'

    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    channel_type = fields.Selection([
        ('email', 'Email'),
        ('teams', 'Microsoft Teams'),
    ], required=True, default='email')
    email_to = fields.Char(string='Recipients', help="Comma separated email addresses.")
    webhook_url = fields.Char(
        string='Webhook URL', groups='base.group_system', copy=False,
        help="Teams Workflows (\"Post to a channel when a webhook request is received\") "
             "or Incoming Webhook URL. Treat it as a secret.")
    min_level = fields.Selection(LEVEL_SELECTION, string='Minimum Level', required=True, default='ERROR')
    include_traceback = fields.Boolean(
        default=True,
        help="Send the (redacted, truncated) traceback. Disable if the channel audience "
             "should not see technical details.")
    last_error = fields.Char(string='Last Delivery Error', readonly=True, copy=False)

    @api.constrains('channel_type', 'email_to')
    def _check_email_to(self):
        for channel in self.filtered(lambda c: c.channel_type == 'email'):
            emails = email_split(channel.email_to or '')
            if not emails or not all(email_normalize(e) for e in emails):
                raise ValidationError(_("Please enter valid recipient email addresses for '%s'.", channel.name))

    @api.constrains('channel_type', 'webhook_url')
    def _check_webhook_url(self):
        for channel in self.sudo().filtered(lambda c: c.channel_type == 'teams'):
            self._validate_webhook_url(channel.webhook_url)

    @api.model
    def _validate_webhook_url(self, url):
        url = url or ''
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        try:
            # the host requests/urllib3 will really connect to: urlparse and
            # urllib3 disagree on some inputs (e.g. "https://127.0.0.1\\.webhook.office.com")
            request_host = (parse_url(requests.Request('POST', url).prepare().url).host or '').lower()
        except Exception:  # noqa: BLE001
            request_host = None
        if parsed.scheme != 'https' or not host.endswith(ALLOWED_WEBHOOK_HOST_SUFFIXES) \
                or request_host != host or re.search(r'[\\\s\x00-\x1f\x7f]', url) \
                or parsed.username or parsed.password:
            raise ValidationError(_(
                "The Teams webhook URL must use HTTPS and point to a Microsoft host (%s).",
                ', '.join('*' + s for s in ALLOWED_WEBHOOK_HOST_SUFFIXES)))

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------

    def _accepts(self, level):
        self.ensure_one()
        return LEVELS.get(level, 0) >= LEVELS[self.min_level]

    def _send_digest(self, items, context_info):
        """Send ``items`` (list of dicts built by the scanner). Never raises.

        :return: True if delivered (email: queued), False on failure,
                 None when nothing matched this channel's level
        """
        self.ensure_one()
        items = [item for item in items if self._accepts(item['level'])]
        if not items:
            return None
        if not self.include_traceback:
            items = [dict(item, traceback=False) for item in items]
        try:
            with self.env.cr.savepoint():
                if self.channel_type == 'email':
                    self._send_email(items, context_info)
                else:
                    self._send_teams(items, context_info)
        except Exception as e:  # noqa: BLE001 - a broken channel must not stop the others
            error = self._safe_error(e)
            # warning (not error) + own logger is excluded from scanning: no feedback loop
            _logger.warning("Log error notifier: delivery to channel %s failed: %s", self.id, error)
            self.sudo().last_error = error[:250]
            return False
        if self.last_error:
            self.sudo().last_error = False
        return True

    def _safe_error(self, error):
        """Error message without the webhook path/query (they carry the signature)."""
        message = str(error)
        url = self.sudo().webhook_url
        if url:
            parsed = urlparse(url)
            for secret in (url, parsed.path, parsed.query):
                if secret and secret != '/':
                    message = message.replace(secret, '***')
        return message

    def _send_email(self, items, context_info):
        body = self.env['ir.qweb']._render('log_error_notifier.log_error_digest_email', {
            'items': items,
            **context_info,
        })
        mail = self.env['mail.mail'].sudo().create({
            'subject': context_info['title'],
            'body_html': body,
            'email_from': self.env['ir.mail_server']._get_default_from_address() or self.env.company.email_formatted,
            'email_to': ','.join(email_split(self.email_to)),
            'auto_delete': True,
        })
        # process the queue soon instead of waiting for the next scheduled run
        self.env.ref('mail.ir_cron_mail_scheduler_action')._trigger()
        return mail

    def _send_teams(self, items, context_info):
        url = self.sudo().webhook_url
        self._validate_webhook_url(url)
        payload = self._teams_payload(items, context_info)
        response = requests.post(
            url, data=payload, timeout=REQUEST_TIMEOUT, allow_redirects=False,
            headers={'Content-Type': 'application/json'},
        )
        if response.status_code >= 300:
            raise UserError(_("Teams webhook returned HTTP %s", response.status_code))

    @api.model
    def _teams_payload(self, items, context_info):
        """Adaptive card. Untrusted log content goes in TextRun elements, which
        are rendered as plain text (no markdown/link injection)."""

        def text_run(text, **kw):
            return {'type': 'TextRun', 'text': text, **kw}

        def build(items, with_traceback):
            body = [
                {'type': 'TextBlock', 'size': 'Medium', 'weight': 'Bolder', 'wrap': True,
                 'text': context_info['title']},
                {'type': 'RichTextBlock', 'inlines': [text_run(
                    'Database: %(db_name)s | Host: %(host)s' % context_info, isSubtle=True)]},
            ]
            for item in items:
                color = 'Attention' if item['level'] in ('ERROR', 'CRITICAL') else 'Warning'
                body.append({'type': 'RichTextBlock', 'separator': True, 'inlines': [
                    text_run('%s x%s ' % (item['level'], item['count']), weight='Bolder', color=color),
                    text_run(item['logger'], isSubtle=True),
                ]})
                body.append({'type': 'RichTextBlock', 'inlines': [text_run(item['summary'])]})
                if with_traceback and item.get('traceback'):
                    body.append({'type': 'RichTextBlock', 'inlines': [
                        text_run(item['traceback'][-1500:], fontType='Monospace', size='Small')]})
            card = {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'type': 'AdaptiveCard',
                'version': '1.4',
                'msteams': {'width': 'Full'},
                'body': body,
            }
            if context_info.get('url'):
                card['actions'] = [{'type': 'Action.OpenUrl', 'title': 'Open in Odoo', 'url': context_info['url']}]
            return json.dumps({
                'type': 'message',
                'attachments': [{'contentType': 'application/vnd.microsoft.card.adaptive', 'content': card}],
            })

        payload = build(items, with_traceback=True)
        if len(payload.encode()) > TEAMS_MAX_PAYLOAD:
            payload = build(items, with_traceback=False)
        while len(payload.encode()) > TEAMS_MAX_PAYLOAD and len(items) > 1:
            items = items[:len(items) // 2]
            payload = build(items, with_traceback=False)
        return payload

    def action_send_test(self):
        self.ensure_one()
        scanner = self.env['log.error.scanner']
        items = [{
            'level': 'CRITICAL',
            'count': 1,
            'logger': 'odoo.addons.log_error_notifier',
            'summary': _("Test notification from Odoo log error notifier."),
            'traceback': 'Traceback (most recent call last):\n  File "test.py", line 1\nException: test',
            'url': False,
        }]
        if not self._send_digest(items, scanner._context_info(_("[TEST] Odoo log alert"))):
            raise UserError(_("Delivery failed: %s", self.last_error))
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {'type': 'success', 'message': _("Test notification sent.")},
        }
