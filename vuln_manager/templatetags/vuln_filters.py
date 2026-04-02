from django import template
import os

register = template.Library()

@register.filter(name='split')
def split(value, key):
    return value.split(key)

@register.filter(name='basename')
def basename(value):
    return os.path.basename(value)

@register.filter(name='replace_underscore')
def replace_underscore(value):
    return value.replace('_', ' ')
