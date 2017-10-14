import requests

from jose import jwt
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class Authentication(BaseAuthentication):
    """
    Token authentication.

    Clients should authenticate by passing the token key in the 'Authorization'
    HTTP header, prepended with the string 'Bearer '.  For example:

    Authorization: Bearer 401f7ac837da42b97f613d789819ff93537bee6a
    """

    keyword = 'Bearer'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token):
        jwks = requests.get('https://' + settings.AUTH0_DOMAIN + '/.well-known/jwks.json').json()

        try:
            unverified_header = jwt.get_unverified_header(token)
        except:
            msg = _('Error decoding headers.')
            raise AuthenticationFailed(msg)

        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=settings.ALGORITHMS,
                    audience=settings.API_AUDIENCE,
                    issuer='https://' + settings.AUTH0_DOMAIN + '/'
                )
            except jwt.ExpiredSignatureError:
                msg = _('Token is expired.')
                raise AuthenticationFailed(msg)
            except jwt.JWTClaimsError:
                msg = _('Incorrect claims, please check the audience and issuer.')
                raise AuthenticationFailed(msg)
            except Exception:
                msg = _('Unable to parse authentication token.')
                raise AuthenticationFailed(msg)

            # Create user if none exists
            try:
                user = User.objects.get(auth0_id=payload.get('sub'))
            except User.DoesNotExist:
                user = User.objects.create(auth0_id=payload.get('sub'))

            return (user, token)

        msg = _('Unable to find appropriate key.')
        raise AuthenticationFailed(msg)

    def authenticate_header(self, request):
        return self.keyword
