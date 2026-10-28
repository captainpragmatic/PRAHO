"""Setup dependencies invalidate a local derived cache after their transaction commits."""

from django.db import transaction
from django.db.models.signals import post_delete, post_save


def _setup_changed(*, using: str, **_kwargs: object) -> None:
    from apps.settings.setup_checklist import clear_setup_cache  # noqa: PLC0415

    transaction.on_commit(clear_setup_cache, using=using)


def connect_setup_dependencies() -> None:
    for sender in (
        "common.LegalDocument",
        "common.EncryptedCredential",
        "products.Product",
        "products.ProductPrice",
        "provisioning.ServicePlan",
        "provisioning.VirtualminServer",
    ):
        for signal in (post_save, post_delete):
            signal.connect(_setup_changed, sender=sender, dispatch_uid=f"setup:{sender}:{id(signal)}", weak=False)
