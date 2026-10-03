# -*- coding: utf-8 -*-
{
    'name': "Log Error Notifier",
    'license': 'LGPL-3',
    'summary': "Scan the Odoo log file for errors and alert by email or MS Teams",
    'description': """
Periodically tails the server log file (``logfile`` in odoo.conf), groups
WARNING/ERROR/CRITICAL entries by fingerprint, and sends a digest to the
configured email recipients and/or Microsoft Teams channels.

* Incremental reading (byte offset + inode), rotation aware, bounded per run
* Deduplication with cooldown, mute noisy errors
* Secrets redacted from messages/tracebacks before they leave the server
* Teams webhooks restricted to Microsoft hosts over HTTPS (no redirects)
* Everything restricted to Settings / Administration users
    """,
    'author': "My Company",
    'category': 'Technical',
    'version': '18.0.1.0.0',
    'depends': ['base', 'mail'],
    'external_dependencies': {'python': ['requests']},
    'data': [
        'security/ir.model.access.csv',
        'data/ir_config_parameter.xml',
        'data/ir_cron.xml',
        'data/mail_templates.xml',
        'views/log_error_event_views.xml',
        'views/log_error_channel_views.xml',
        'views/res_config_settings_views.xml',
        'views/menus.xml',
    ],
    'installable': True,
    'application': False,
}
