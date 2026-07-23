from odoo import http, fields
from odoo.http import request
from odoo.exceptions import ValidationError, UserError
from odoo.addons.portal.controllers.portal import CustomerPortal


class PortalCustomerLeaves(CustomerPortal):

    def _prepare_home_portal_values(self, counters):
        values = super()._prepare_home_portal_values(counters)
        if 'leave_count' in counters:
            user = request.env.user
            employee = request.env['hr.employee'].sudo().search([('user_id', '=', user.id)], limit=1)
            if employee:
                values['leave_count'] = request.env['hr.leave'].sudo().search_count([
                    ('employee_id', '=', employee.id)
                ])
            else:
                values['leave_count'] = 0
            print("Values =", values)
        return values

    def _get_current_employee(self):
        return request.env['hr.employee'].search([('user_id', '=', request.env.user.id)], limit=1)

    def _get_remaining_days(self, employee, leave_type):
        allocation_data = leave_type.get_allocation_data(employee)
        print("allocation_data>>>", allocation_data)
        entries = allocation_data.get(employee, [])
        print("entries>", entries)
        if entries:
            return entries[0][1].get('virtual_remaining_leaves', 0)
        return 0

    @http.route(['/my/leaves'], type='http', auth="user", website=True)
    def portal_my_leaves(self, **kw):
        employee = self._get_current_employee()
        leaves = []
        if employee:
            leaves = request.env['hr.leave'].sudo().search([
                ('employee_id', '=', employee.id)
            ], order="date_from desc")

        values = {
            'leaves': leaves,
            'page_name': 'leave',
        }
        return request.render("portal_holidays.portal_my_leaves_list", values)

    @http.route(['/my/leaves/new'], type='http', auth="user", website=True)
    def portal_my_leaves_new(self, **kw):
        employee = self._get_current_employee()
        leave_types = request.env['hr.leave.type'].sudo().search([])

        holiday_status_id = kw.get('holiday_status_id')
        date_from = kw.get('date_from')
        date_to = kw.get('date_to')

        remaining = None
        warning = None

        if employee and holiday_status_id:
            leave_type = request.env['hr.leave.type'].sudo().browse(int(holiday_status_id))
            remaining = self._get_remaining_days(employee, leave_type)

            if date_from and date_to:
                df = fields.Date.from_string(date_from)
                dt = fields.Date.from_string(date_to)
                if dt >= df:
                    requested_days = (dt - df).days + 1
                    if requested_days > remaining:
                        warning = (
                            f"Requested Days ({requested_days}) "
                            f"More Than Availabilty Days ({remaining})"
                        )
                else:
                    warning = "Date from must br before Date To"

        values = {
            'leave_types': leave_types,
            'page_name': 'leave_new',
            'error': kw.get('error'),
            'warning': warning,
            'remaining': remaining,
            'default_date_from': date_from,
            'default_date_to': date_to,
            'default_leave_type_id': holiday_status_id,
        }
        return request.render("portal_holidays.portal_my_leave_new", values)

    @http.route(['/my/leaves/submit'], type='http', auth="user", website=True, methods=['POST'])
    def portal_my_leaves_submit(self, **post):
        employee = self._get_current_employee()
        if not employee:
            return request.redirect('/my/leaves')

        holiday_status_id = post.get('holiday_status_id')
        date_from = post.get('date_from')
        date_to = post.get('date_to')

        if not (holiday_status_id and date_from and date_to):
            return request.redirect('/my/leaves/new?error=' + 'Please write the required fields')

        leave_type = request.env['hr.leave.type'].sudo().browse(int(holiday_status_id))
        df = fields.Date.from_string(date_from)
        dt = fields.Date.from_string(date_to)

        if dt < df:
            return request.redirect(
                f'/my/leaves/new?error=Date from must br before Date To'
                f'&holiday_status_id={holiday_status_id}'
            )

        requested_days = (dt - df).days + 1
        remaining = self._get_remaining_days(employee, leave_type)

        if requested_days > remaining:
            error = f"Required Days ({requested_days}) More than Availability Days ({remaining})"
            return request.redirect(
                f'/my/leaves/new?error={error}&date_from={date_from}'
                f'&date_to={date_to}&holiday_status_id={holiday_status_id}'
            )


        request.env['hr.leave'].sudo().create({
                'employee_id': employee.id,
                'holiday_status_id': leave_type.id,
                'date_from': date_from,
                'date_to': date_to,
            })
        return request.redirect('/my/leaves')

