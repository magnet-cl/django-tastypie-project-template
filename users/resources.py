#!/usr/bin/python
# coding=utf-8
# vim: set fileencoding=utf-8 :
"""
This document defines the UserResource, which represents a user in the api.

"""
# api
from api.authentication import MethodWardAuthentication
from api.decorators import api_method
from api.decorators import required_fields
from api.resources import MultipartResource

# django
from django.conf.urls import url
from django.contrib.auth import authenticate, login, logout

# models
from users.models import User

# tastypie
from tastypie import fields
from tastypie import http
from tastypie.authorization import Authorization
from tastypie.exceptions import ImmediateHttpResponse
from tastypie.exceptions import Unauthorized
from tastypie.utils import trailing_slash

# standard library
import json
import logging

# Get an instance of a logger
logger = logging.getLogger('api.user')


class UserAuthorization(Authorization):

    def delete_detail(self, object_list, bundle):
        """
        Returns either ``True`` if the user is allowed to delete the object in
        question or throw ``Unauthorized`` if they are not.
        """
        raise Unauthorized("You don't have permissions to do this")

    def update_detail(self, object_list, bundle):
        """
        Returns either ``True`` if the user is allowed to update the object in
        question or throw ``Unauthorized`` if they are not.
        """
        if bundle.request.user.id != bundle.obj.id:
            raise Unauthorized("You don't have permissions to do this")

        return True


class UserResource(MultipartResource):
    """ Resource model for the User model """

    date_joined = fields.DateTimeField(
        'date_joined',
        readonly=True,
        help_text='When the user registered',
    )

    class Meta(MultipartResource.Meta):
        """ Metadata for the user resource """
        queryset = User.objects.all()
        resource_name = 'users'
        allowed_methods = ['get', 'post', 'patch']
        authentication = MethodWardAuthentication(
            annonymus_allowed_methods=['post']
        )
        authorization = UserAuthorization()

        excludes = [
            'password',
            'is_staff',
            'email',
            'is_superuser',
            'is_active',
        ]

        extra_actions = [{
            "name": "is_authenticated",
            "http_method": "GET",
            "resource_type": "list",
            "summary": "Returns user data if he is authenticated",
            "fields": {
            }
        }, {
            "name": "login",
            "http_method": "POST",
            "resource_type": "list",
            "summary": "Authenticates a user in the API.",
            "fields": {
                "email": {
                    "type": "string",
                    "required": True,
                    "description": "The email of the user"
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "The password of the user"
                }
            }
        }, {
            "name": "logout",
            "http_method": "DELETE",
            "resource_type": "list",
            "summary": "Logout endpoint",
            "fields": {
            }
        }, {
            "name": "recover_password",
            "http_method": "POST",
            "resource_type": "list",
            "summary": "Request a recover password email",
            "fields": {
                "email": {
                    "type": "string",
                    "required": True,
                    "description": "The email of the account to recover"
                }
            }
        }]

    def prepend_urls(self):
        """ Add the following array of urls to the UserResource base urls """
        resource_name = self._meta.resource_name
        return [
            # register
            url(r"^(?P<resource_name>%s)/register%s$" %
                (resource_name, trailing_slash()),
                self.wrap_view('register'), name="api_register"),
            # login
            url(r"^(?P<resource_name>%s)/login%s$" %
                (resource_name, trailing_slash()),
                self.wrap_view('login'), name="api_login"),
            # logout
            url(r'^(?P<resource_name>%s)/logout%s$' %
                (resource_name, trailing_slash()),
                self.wrap_view('logout'), name='api_logout'),
            # is_authenticated
            url(r'^(?P<resource_name>%s)/is_authenticated%s$' %
                (resource_name, trailing_slash()),
                self.wrap_view('authenticated'), name='api_authenticated'),
            # recover password
            url(r'^(?P<resource_name>%s)/recover_password%s$' %
                (resource_name, trailing_slash()),
                self.wrap_view('recover_password'),
                name='api_recover_password'),
        ]

    def authenticated(self, request, **kwargs):
        """ api method to check whether a user is authenticated or not"""

        self.method_check(request, allowed=['get'])
        user = request.user
        if user.is_authenticated():

            bundle = self.build_bundle(obj=user, request=request)
            bundle = self.full_dehydrate(bundle)
            bundle = self.alter_detail_data_to_serialize(request, bundle)

            return self.create_response(request, bundle)
        else:
            return self.create_response(request, False)

    def recover_password(self, request, **kwargs):
        """ Sets a token to recover the password and sends an email with
        the token

        """
        self.method_check(request, allowed=['post'])

        data = self.deserialize(
            request, request.body,
            format=request.META.get('CONTENT_TYPE', 'application/json')
        )
        email = data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            response = http.HttpBadRequest(
                json.dumps("User with email %s not found" % email),
                content_type=request.META['CONTENT_TYPE'])
            raise ImmediateHttpResponse(response=response)

        user.send_recover_password_email(request)

        return self.create_response(request, {'success': True})

    @api_method(single=True, expected_methods=['post'])
    def login(self, request, **kwargs):
        """ A new end point for login the user using the django login system

        """
        logger.debug('UserResource.login')

        logger.debug('UserResource.login: Content Type: '.format(
                     request.META.get('CONTENT_TYPE')))

        data = self.deserialize(
            request, request.body,
            format=request.META.get('CONTENT_TYPE', 'application/json')
        )

        logger.debug('UserResource.login: {}'.format(json.dumps(data)))

        email = data.get('email', '')
        password = data.get('password', '')

        user = authenticate(email=email, password=password)

        if user:
            logger.debug('UserResource.login: user found')
            if user.is_active:
                logger.debug('UserResource.login: login successful')
                login(request, user)
                return user
            else:
                logger.debug('UserResource.login: login fail, user not active')
                res = http.HttpForbidden(
                    json.dumps('disabled'),
                    content_type=request.META['CONTENT_TYPE'])
                raise ImmediateHttpResponse(response=res)
        else:
            res = http.HttpUnauthorized(
                json.dumps('invalid email or password'),
                content_type=request.META['CONTENT_TYPE'])
            raise ImmediateHttpResponse(response=res)

    def logout(self, request, **kwargs):
        """
        A new end point to logout the user using the django login system
        """
        self.method_check(request, allowed=['delete'])
        if request.user and request.user.is_authenticated():
            logout(request)

        return self.create_response(request, {'success': True})

    @required_fields(['email', 'first_name', 'last_name', 'password'])
    def obj_create(self, bundle, **kwargs):
        """
        A new end point for login the user using the django login system
        """
        logger.debug('UserResource.obj_create')

        data = bundle.data
        email = data['email'].lower()

        # try to geet the user by email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # the user with this email does not exist
            # create a new user
            user = User.objects.create(
                email=email,
                first_name=data['first_name'],
                last_name=data['last_name'])
            user.set_password(data['password'])
            user.save()

        user = authenticate(email=email, password=data['password'])

        try:
            login(bundle.request, user)
        except:
            response = http.HttpConflict(
                json.dumps("This email is already registered"),
                content_type=bundle.request.META['CONTENT_TYPE'])
            raise ImmediateHttpResponse(response=response)

        bundle.obj = user
        return bundle
