from django.urls import include, path

from django.contrib import admin
from django.views.debug import default_urlconf

urlpatterns = [
    # Examples:
    path('', default_urlconf),
    # url(r'^$', 'profit.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    path('admin/', admin.site.urls),
]

# rest api
#
#urlpatterns += [    
#]
