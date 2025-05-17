import utils.http_session
import utils.transport
import utils.session
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Nitro_Track.settings')


application = get_wsgi_application()
