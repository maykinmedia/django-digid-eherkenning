from urllib.parse import urlencode

from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView

from digid_eherkenning.mock import conf


class _MockBaseView(TemplateView):
    def get_context_data(self, **kwargs):
        return {
            'app_title': conf.get_app_title(),
            **super().get_context_data(**kwargs)
        }


class MockIndexView(_MockBaseView):
    template_name = 'project/index.html'

    def get_context_data(self, **kwargs):
        url = reverse('digid:login')
        params = {
            'next': self.request.build_absolute_uri(reverse('test-success'))
        }
        return {
            'login_url': f"{url}?{urlencode(params)}",
            **super().get_context_data(**kwargs)
        }


class MockSuccessView(LoginRequiredMixin, _MockBaseView):
    template_name = 'project/success.html'
