"""Task consumers must honor Retriability, never infer replay safety from text."""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.common.types import Err, Retriability
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_models import VirtualminAccount


class ProvisioningFailureHandlerRetryContractTests(SimpleTestCase):
    def test_unknown_error_text_does_not_trigger_retry(self) -> None:
        service = MagicMock()
        service.id = "service-1"
        service.customer.id = "customer-1"

        with (
            patch.object(virtualmin_tasks.AuditService, "log_event"),
            patch.object(virtualmin_tasks, "log_security_event_safe"),
        ):
            result = virtualmin_tasks._handle_failed_provisioning_secure(
                "connection timeout after request was sent",
                service,
                "example.com",
                "correlation-1",
                {"service_id": "service-1"},
                retriability=Retriability.UNKNOWN,
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)

    def test_explicit_retriable_uses_dedicated_exception(self) -> None:
        service = MagicMock()
        service.id = "service-1"
        service.customer.id = "customer-1"

        with (
            patch.object(virtualmin_tasks.AuditService, "log_event"),
            patch.object(virtualmin_tasks, "log_security_event_safe"),
            self.assertRaises(Exception) as raised,
        ):
            virtualmin_tasks._handle_failed_provisioning_secure(
                "upstream rejected before accepting request",
                service,
                "example.com",
                "correlation-1",
                {"service_id": "service-1"},
                retriability=Retriability.RETRIABLE,
            )

        self.assertEqual(type(raised.exception).__name__, "RetryableProvisioningError")

    def test_create_path_passes_inner_retriability_to_handler(self) -> None:
        service = MagicMock()
        service.id = "service-1"
        params = virtualmin_tasks.ProvisioningExecutionParams(
            service=service,
            domain="example.com",
            username="owner",
            template="Default",
            server=None,
            correlation_id="correlation-1",
            safe_log_ctx={"service_id": "service-1"},
        )
        inner = Err("permanent rejection", retriability=Retriability.NOT_RETRIABLE)

        with (
            patch.object(virtualmin_tasks, "VirtualminProvisioningService") as service_cls,
            patch.object(
                virtualmin_tasks,
                "_handle_failed_provisioning_secure",
                return_value={"success": False},
            ) as handler,
        ):
            service_cls.return_value.create_virtualmin_account.return_value = inner
            virtualmin_tasks._execute_virtualmin_provisioning_with_params(params)

        handler.assert_called_once_with(
            "permanent rejection",
            service,
            "example.com",
            "correlation-1",
            {"service_id": "service-1"},
            retriability=Retriability.NOT_RETRIABLE,
        )


    def test_critical_unknown_timeout_text_does_not_trigger_retry(self) -> None:
        with (
            patch.object(virtualmin_tasks.AuditService, "log_event"),
            patch.object(virtualmin_tasks, "log_security_event_safe"),
        ):
            result = virtualmin_tasks._handle_critical_provisioning_error_secure(
                RuntimeError("connection timeout after request was sent"),
                "example.com",
                "service-1",
                "correlation-1",
                {"service_id": "service-1"},
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)

    def test_critical_explicit_retriable_error_is_re_raised(self) -> None:
        error = virtualmin_tasks.RetryableProvisioningError("safe replay requested")

        with (
            patch.object(virtualmin_tasks.AuditService, "log_event"),
            patch.object(virtualmin_tasks, "log_security_event_safe"),
            self.assertRaises(virtualmin_tasks.RetryableProvisioningError),
        ):
            virtualmin_tasks._handle_critical_provisioning_error_secure(
                error,
                "example.com",
                "service-1",
                "correlation-1",
                {"service_id": "service-1"},
            )

    def test_transaction_re_raises_only_explicit_retry_exception(self) -> None:
        context = virtualmin_tasks.ProvisioningContext(
            service_id="service-1",
            domain="example.com",
            username="owner",
            template="Default",
            correlation_id="correlation-1",
            safe_log_ctx={"service_id": "service-1"},
            idempotency_key="idem-1",
        )
        retry_error = virtualmin_tasks.RetryableProvisioningError("safe replay requested")

        with (
            patch.object(virtualmin_tasks.transaction, "atomic"),
            patch.object(
                virtualmin_tasks,
                "_validate_service_for_provisioning_secure",
                return_value={"success": True, "service": MagicMock()},
            ),
            patch.object(virtualmin_tasks, "_check_existing_virtualmin_account_secure", return_value=None),
            patch.object(virtualmin_tasks, "_get_provisioning_server_secure", return_value=None),
            patch.object(virtualmin_tasks, "_execute_virtualmin_provisioning_with_params", side_effect=retry_error),
            patch.object(virtualmin_tasks.IdempotencyManager, "clear"),
            patch.object(virtualmin_tasks.logger, "error") as error_log,
            patch.object(virtualmin_tasks.logger, "warning") as warning_log,
            self.assertRaises(virtualmin_tasks.RetryableProvisioningError),
        ):
            virtualmin_tasks._execute_provisioning_transaction(context, None)

        error_log.assert_not_called()
        warning_log.assert_called_once()

    def test_transaction_does_not_retry_unknown_timeout_text(self) -> None:
        context = virtualmin_tasks.ProvisioningContext(
            service_id="service-1",
            domain="example.com",
            username="owner",
            template="Default",
            correlation_id="correlation-1",
            safe_log_ctx={"service_id": "service-1"},
            idempotency_key="idem-1",
        )

        with (
            patch.object(virtualmin_tasks.transaction, "atomic"),
            patch.object(
                virtualmin_tasks,
                "_validate_service_for_provisioning_secure",
                return_value={"success": True, "service": MagicMock()},
            ),
            patch.object(virtualmin_tasks, "_check_existing_virtualmin_account_secure", return_value=None),
            patch.object(virtualmin_tasks, "_get_provisioning_server_secure", return_value=None),
            patch.object(
                virtualmin_tasks,
                "_execute_virtualmin_provisioning_with_params",
                side_effect=RuntimeError("connection timeout after request was sent"),
            ),
            patch.object(virtualmin_tasks.IdempotencyManager, "clear"),
            patch.object(virtualmin_tasks.logger, "error") as error_log,
        ):
            result = virtualmin_tasks._execute_provisioning_transaction(context, None)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Provisioning error: connection timeout after request was sent")
        self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)
        error_log.assert_called_once_with(
            "🔥 [VirtualminTask] Provisioning transaction failed: connection timeout after request was sent"
        )

    def test_task_entrypoint_preserves_explicit_retry_exception(self) -> None:
        context = virtualmin_tasks.ProvisioningContext(
            service_id="service-1",
            domain="example.com",
            username="owner",
            template="Default",
            correlation_id="correlation-1",
            safe_log_ctx={"service_id": "service-1"},
            idempotency_key="idem-1",
        )
        retry_error = virtualmin_tasks.RetryableProvisioningError("safe replay requested")

        with (
            patch.object(
                virtualmin_tasks,
                "_decrypt_and_extract_parameters",
                return_value=({}, "service-1", "example.com"),
            ),
            patch.object(virtualmin_tasks, "_validate_provisioning_parameters", return_value=context),
            patch.object(virtualmin_tasks, "_check_idempotency", return_value=(True, None)),
            patch.object(
                virtualmin_tasks,
                "_execute_provisioning_transaction",
                side_effect=retry_error,
            ),
            patch.object(virtualmin_tasks.AuditService, "log_event"),
            patch.object(virtualmin_tasks, "log_security_event_safe"),
            self.assertRaises(virtualmin_tasks.RetryableProvisioningError),
        ):
            virtualmin_tasks.provision_virtualmin_account(MagicMock())


class AccountTaskRetryContractTests(SimpleTestCase):
    task_cases = (
        ("suspend_virtualmin_account", "suspend_account", ("account-1", "reason")),
        ("unsuspend_virtualmin_account", "unsuspend_account", ("account-1",)),
        ("delete_virtualmin_account", "delete_account", ("account-1",)),
    )

    def _account(self) -> MagicMock:
        account = MagicMock()
        account.id = "account-1"
        account.domain = "example.com"
        account.server = MagicMock()
        return account

    def test_unknown_timeout_text_never_triggers_account_mutation_retry(self) -> None:
        for task_name, service_method, args in self.task_cases:
            with self.subTest(task=task_name):
                account = self._account()
                with (
                    patch.object(VirtualminAccount.objects, "get", return_value=account),
                    patch.object(virtualmin_tasks, "VirtualminProvisioningService") as service_cls,
                ):
                    getattr(service_cls.return_value, service_method).return_value = Err(
                        "connection timeout after request was sent",
                        retriability=Retriability.UNKNOWN,
                    )
                    result = getattr(virtualmin_tasks, task_name)(*args)

                self.assertFalse(result["success"])
                self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)

    def test_explicit_retriable_failure_triggers_account_mutation_retry(self) -> None:
        for task_name, service_method, args in self.task_cases:
            with self.subTest(task=task_name):
                account = self._account()
                with (
                    patch.object(VirtualminAccount.objects, "get", return_value=account),
                    patch.object(virtualmin_tasks, "VirtualminProvisioningService") as service_cls,
                    self.assertRaises(Exception) as raised,
                ):
                    getattr(service_cls.return_value, service_method).return_value = Err(
                        "safe replay requested",
                        retriability=Retriability.RETRIABLE,
                    )
                    getattr(virtualmin_tasks, task_name)(*args)

                self.assertEqual(type(raised.exception).__name__, "RetryableProvisioningError")

    def test_unexpected_account_mutation_exception_is_not_retried(self) -> None:
        for task_name, service_method, args in self.task_cases:
            with self.subTest(task=task_name):
                account = self._account()
                with (
                    patch.object(VirtualminAccount.objects, "get", return_value=account),
                    patch.object(virtualmin_tasks, "VirtualminProvisioningService") as service_cls,
                ):
                    getattr(service_cls.return_value, service_method).side_effect = RuntimeError("response lost")
                    result = getattr(virtualmin_tasks, task_name)(*args)

                self.assertFalse(result["success"])
                self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)
