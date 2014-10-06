""" this document defines the project urls """

# django
from django.conf.urls import patterns, include, url

# resources
from users.resources import UserResource

# tastypie
from tastypie.api import Api

# api
from api.serializers import Serializer


api = Api(api_name='v1', serializer_class=Serializer)

api.register(UserResource())

urlpatterns = patterns(
    '',
    url(r'doc/', include('tastypie_swagger.urls',
                         namespace='tastypie_swagger')),
    (r'', include(api.urls)),
)
