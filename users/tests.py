"""
Unit tests for the users app
"""

# django

# tests
from api.tests import BaseResourceTestCase
from base.tests import BaseTestCase

# models

# api

# standard library


class StatusResourceTestCase(BaseResourceTestCase):

    def setUp(self):
        super(StatusResourceTestCase, self).setUp()

    def test_recover_password(self):

        data = {
            'email': self.user.email,
        }

        # check the happy path
        self.post(
            resource='users',
            data=data,
            endpoint='recover_password'
        )

        # check the email does not exist response (bad request)
        data['email'] = self.random_string(length=6) + data['email']

        self.post(
            resource='users',
            data=data,
            endpoint='recover_password',
            expected_code=400,
        )


class UserTest(BaseTestCase):
    def test_lower_case_emails(self):
        """
        Tests that users are created with lower case emails
        """
        self.user.email = "Hello@magnet.cl"
        self.user.save()
        self.assertEqual(self.user.email, 'hello@magnet.cl')
