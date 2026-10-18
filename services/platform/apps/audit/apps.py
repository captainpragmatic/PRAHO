from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.audit"
    verbose_name = "Audit & Compliance"

    def ready(self) -> None:
        """Import signal handlers when app is ready."""
        from django_q.signals import post_execute, pre_execute

        from . import signals
        from .actor_context import clear_actor_for_task, restore_actor_after_task

        signals.register_audit_signals()

        # A task acts for nobody: it must not inherit whoever ran before it in this process.
        pre_execute.connect(clear_actor_for_task, dispatch_uid="audit_clear_actor_for_task")
        post_execute.connect(restore_actor_after_task, dispatch_uid="audit_restore_actor_after_task")
