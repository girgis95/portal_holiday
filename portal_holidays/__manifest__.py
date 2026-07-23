{
    'name': 'Employee Portal Holidays',
    'version': '18.0.0.1',
    'category': 'Human Resources',
    'summary': '',
    'description': """
    """,
    'author': "Girgis Moneer",
    'price': '10.0',
    # 'currency': 'USD',
    # 'website': 'https://areterix.com',
    'depends': ['hr_attendance','hr_holidays', 'portal'],
    'data': [
        'views/portal_customer_leave_views.xml'
    ],
    'assets': {

    },
    'license': 'LGPL-3',
    'installable': True,
    'application': True,
}
