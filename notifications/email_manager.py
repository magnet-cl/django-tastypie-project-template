# django
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import Context
from django.template.loader import get_template
from django.utils.translation import ugettext_lazy as _

# standard library
from threading import Thread
import time

# base
from base import utils


def _send_emails(emails, template_name, subject, sender=None,
                 context=None, fail_silently=False,
                 attachments=None, headers=None):
    """ Sends an email to a list of emails using a given template name """

    if context is None:
        context = {}

    if attachments is None:
        attachments = []

    if not settings.ENABLE_EMAILS:
        return

    text_template = get_template("emails/%s.txt" % template_name)
    html_template = get_template("emails/%s.html" % template_name)
    context = Context(context)

    text_content = text_template.render(context)
    html_content = html_template.render(context)

    sender = "%s <%s>" % (settings.EMAIL_SENDER_NAME, settings.SENDER_EMAIL)

    emails_in_groups_of_5 = utils.grouper(emails, 5)

    for emails in emails_in_groups_of_5:
        msg = EmailMultiAlternatives(subject, text_content,
                                     sender, emails, headers=headers)

        for attachment in attachments:
            attachment.seek(0)
            msg.attach(attachment.name, attachment.read(),
                       'application/pdf')

        msg.attach_alternative(html_content, "text/html")

        # do not send emails if in testing
        if not settings.TEST:
            return

        try:
            msg.send(fail_silently=fail_silently)
        except:
            time.sleep(1)
            msg.send(fail_silently=fail_silently)


def send_emails(**kwargs):
    """
    Sends an email to a list of emails using a given template name
    """
    t = Thread(target=send_emails, kwargs=kwargs)
    t.start()


def send_example_email(email):
    """
    Sends an email to test the email funcionality.
    """
    subject = _("Hello")
    template_name = "example_email"

    send_emails(
        emails=(email,),
        template_name=template_name,
        subject=subject,
        context={},
    )
