from django.views import View


def get_next_page(view: View) -> str:
    try:
        return view.get_default_redirect_url()  # type: ignore
    except AttributeError:
        return view.get_next_page()  # type: ignore
