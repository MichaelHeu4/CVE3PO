from django import template
import os

register = template.Library()


@register.simple_tag(takes_context=True)
def qs_replace(context, **kwargs):
    """Rebuild the current querystring with overrides.

    Preserves existing GET params (search ``q``, filters, ``sort``/``dir``) and
    only changes the keys passed in. A value of ``None`` or ``""`` drops that
    key. Returns a ``?a=1&b=2`` fragment (or ``""`` when empty).

    Usage: ``<a href="{% qs_replace sort='name' dir='asc' page=None %}">``
    """
    request = context.get("request")
    if not request:
        return ""
    params = request.GET.copy()
    for key, value in kwargs.items():
        if value is None or value == "" or str(value).lower() == "none":
            params.pop(key, None)
        else:
            params[key] = value
    encoded = params.urlencode()
    return f"?{encoded}" if encoded else ""


@register.simple_tag
def sort_dir(current_key, target_key, current_dir):
    """Direction a header link should request: toggle if active, else 'asc'."""
    if current_key == target_key:
        return "desc" if current_dir == "asc" else "asc"
    return "asc"

@register.filter(name='split')
def split(value, key):
    return value.split(key)

@register.filter(name='basename')
def basename(value):
    return os.path.basename(value)

@register.filter(name='replace_underscore')
def replace_underscore(value):
    return value.replace('_', ' ')
