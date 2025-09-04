"""
PRAHO Platform UI Widgets
Custom Django form widgets that integrate with our component library.
"""

from typing import Any

from django import forms


class PRAHOTextWidget(forms.TextInput):
    """Text input widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-slate-100 placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHOTextAreaWidget(forms.Textarea):
    """Textarea widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-slate-100 placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500",
            "rows": 4,
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHOSelectWidget(forms.Select):
    """Select widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHOCheckboxWidget(forms.CheckboxInput):
    """Checkbox widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "h-4 w-4 rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-slate-800"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHOPasswordWidget(forms.PasswordInput):
    """Password input widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-slate-100 placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHONumberWidget(forms.NumberInput):
    """Number input widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-slate-100 placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)


class PRAHOFileWidget(forms.FileInput):
    """File input widget with PRAHO styling."""

    def __init__(self, attrs: dict[str, Any] | None = None) -> None:
        default_attrs = {
            "class": "block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(attrs=default_attrs)
