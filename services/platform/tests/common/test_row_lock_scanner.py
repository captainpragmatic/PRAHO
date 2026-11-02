"""Discovery canaries for locking/eager-loading queries, including variable flow."""

from pathlib import Path

from django.test import SimpleTestCase

from apps.common.row_lock_scanner import lock_join_lines


class RowLockScannerTests(SimpleTestCase):
    maxDiff = None
    def test_platform_has_no_combined_queries(self) -> None:
        root = Path(__file__).resolve().parents[2] / "apps"
        offenders = [f"{path.relative_to(root)}:{line}" for path in sorted(root.rglob("*.py"))
                     if "migrations" not in path.parts for line in lock_join_lines(path.read_text())]
        self.assertEqual(offenders, [])

    def test_billing_has_no_combined_queries(self) -> None:
        root = Path(__file__).resolve().parents[2] / "apps" / "billing"
        offenders = [f"{path.relative_to(root)}:{line}" for path in sorted(root.rglob("*.py"))
                     if "migrations" not in path.parts for line in lock_join_lines(path.read_text())]
        self.assertEqual(offenders, [])

    def test_exact_fixture_inventory_including_final_conditional_cleanup(self) -> None:
        source = '''
a = M.objects.select_for_update().select_related("customer").get(pk=1)
b = M.objects.select_related("service").filter(pk=1).select_for_update(of=("self",)).first()
c = M.objects.select_related("plan")
c = c.filter(active=True)
c = c.select_for_update()
list(c)
d = M.objects.select_for_update()
if include_provider:
    d = d.select_related("provider")
list(d)
e = M.objects.select_related("customer")
if use_lock:
    e = e.select_for_update()
else:
    e = e.filter(enabled=True)
list(e)
final_cleanup = M.objects.select_for_update(of=("self",))
if include_provider:
    final_cleanup = final_cleanup.select_related("server__provider")
return final_cleanup.get(pk=pk)
'''
        self.assertEqual(lock_join_lines(source), [2, 3, 6, 8, 14, 18])
        self.assertEqual(len(lock_join_lines(source)), 6)
        self.assertIn(18, lock_join_lines(source))

    def test_cleared_joins_projection_reassignment_and_separate_prefetch_are_safe(self) -> None:
        cases = [
            'M.objects.select_related("a").select_for_update().select_related(None).get(pk=1)',
            'M.objects.select_for_update().select_related("a").values_list("pk", flat=True)',
            'a = M.objects.select_related("a")\na = M.objects.select_for_update()\nlist(a)',
            'a = M.objects.select_related("a")\na = a.select_related(None).select_for_update()\nlist(a)',
            'a = M.objects.select_for_update().get(pk=1)\nb = M.objects.select_related("s").get(pk=1)',
            'M.objects.select_for_update().prefetch_related("children").get(pk=1)',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), [])

    def test_sliced_lock_still_loads_related_rows(self) -> None:
        self.assertEqual(lock_join_lines('list(M.objects.select_for_update().select_related("a")[:2])'), [1])

    def test_queryset_factory_chains_are_discovered(self) -> None:
        self.assertEqual(lock_join_lines('_eligible().select_for_update().select_related("server").first()'), [1])

    def test_method_argument_materialization_and_negated_truthiness(self) -> None:
        cases = [
            'rows.extend(M.objects.select_for_update().select_related("customer"))',
            'if not M.objects.select_for_update().select_related("customer"):\n    pass',
            'rows = M.objects.select_for_update().select_related("customer")\nif not rows:\n    pass\nrows = None',
            'if M.objects.select_for_update().select_related("customer") and enabled:\n    pass',
            'assert M.objects.select_for_update().select_related("customer")',
            'all([M.objects.select_for_update().select_related("customer")])',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), [1])

    def test_real_conditional_provider_cleanup_shape(self) -> None:
        source = '''def _guard(self, lock=False):
    rows = NodeDeployment.objects.select_related("provider")
    if lock:
        rows = rows.select_for_update(of=("self",))
    current = rows.get(pk=self.deployment.pk)
    return current
'''
        self.assertEqual(lock_join_lines(source), [4])

    def test_conditional_expression_and_comprehension_conditions_are_discovered(self) -> None:
        query = 'M.objects.select_for_update().select_related("customer")'
        cases = [
            f'answer = "yes" if {query} else "no"',
            f'answer = "yes" if {query}.first() else "no"',
            f'answer = [item for item in items if {query}]',
            f'answer = [item for item in items if {query}.first()]',
            f'rows += {query}',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), [1])
