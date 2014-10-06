# -*- coding: utf-8 -*-
""" Models for the users application.

All apps should use the users.User model for all users
"""
# django
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site
from django.db import models
from django.template import loader
from django.utils import timezone
from django.utils.http import int_to_base36
from django.utils.translation import ugettext_lazy as _
from django.utils.translation import ugettext_noop

# managers
from users.managers import UserManager

# models
from base.models import BaseModel

# notifications
from notifications import email_manager

# standard library

# mark for translation the app name
ugettext_noop("Users")


class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    """
    User model with admin-compliant permissions, and BaseModel characteristics

    Email and password are required. Other fields are optional.
    """

    # required fields
    email = models.EmailField(
        _('email address'), unique=True, db_index=True,
        help_text=_("An email address that identifies this user")
    )
    # optional fields
    first_name = models.CharField(
        _('first name'), max_length=30, blank=True,
        help_text=_("The first name of this user"),
    )
    last_name = models.CharField(
        _('last name'), max_length=30, blank=True,
        help_text=_("The last name of this user"),
    )
    is_staff = models.BooleanField(
        _('staff status'), default=False,
        help_text=_('Designates whether the user can log into this admin '
                    'site.'),
    )
    is_active = models.BooleanField(
        _('active'), default=True,
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'),
    )
    # auto fields
    date_joined = models.DateTimeField(
        _('date joined'), default=timezone.now,
        help_text=_("The date this user was created in the database"),
    )
    # Use UserManager to get the create_user method, etc.
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    # public methods
    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    # overwritten methods
    def save(self, *args, **kwargs):
        """ store all emails in lowercase """
        self.email = self.email.lower()

        super(User, self).save(*args, **kwargs)

    def send_example_email(self):
        email_manager.send_example_email(self.email)

    def send_recover_password_email(self, request):
        """
        Sends an email with the required token so a user can recover
        his/her password

        """
        template = "password_reset"

        current_site = get_current_site(request)
        site_name = current_site.name
        domain = current_site.domain

        template_vars = {
            'email': self.email,
            'domain': domain,
            'site_name': site_name,
            'uid': int_to_base36(self.pk),
            'user': self,
            'token': default_token_generator.make_token(self),
            'protocol': 'http',
        }

        subject_template_name = 'registration/password_reset_subject.txt'
        title = loader.render_to_string(subject_template_name, template_vars)

        email_manager.send_emails(
            emails=(self.email,),
            template_name=template,
            subject=title,
            context=template_vars
        )
