"""incomeexpensesapi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.conf.urls import handler404


from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi



schema_view = get_schema_view(
   openapi.Info(
      title="Testing API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="saddamfreelance93@gmail.com"),
      license=openapi.License(name="Saddam License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/',include('authentication.urls')),
    path('api/expenses/',include('expenses.urls')),
    path('api/income/',include('income.urls')),
    path('api/userstats/',include('userstats.urls')),
    path('api/social_auth/', include(('social_auth.urls', 'social_auth'),
                                 namespace="social_auth")),
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/api.json/', schema_view.with_ui(cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
# handler404 = error_page
# # handler404='utils.views.error_404'
# handler500='utils.views.error_500'
# print( [i for i in range(0,5)])
# a = [1 if i%2==0 else 0 for i in range(0,5)] 
# print(a)
