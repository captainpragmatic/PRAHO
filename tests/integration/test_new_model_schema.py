"""New tables have deliberate names and useful descriptions; old tables stay stable."""

from scripts.check_new_model_schema import schema_issues


def migration(options: str) -> str:
    return f"operations = [migrations.CreateModel(name='Delivery', fields=[], options={options})]"


def test_new_model_requires_an_explicit_table_name() -> None:
    assert any("db_table" in issue for issue in schema_issues(migration("{}"), "notifications"))


def test_new_model_requires_a_table_description() -> None:
    issues = schema_issues(migration("{'db_table': 'notification_deliveries'}"), "notifications")
    assert any("db_table_comment" in issue for issue in issues)


def test_valid_table_can_have_complex_unrelated_migration_options() -> None:
    source = migration(
        "{'db_table': 'notification_deliveries', 'db_table_comment': 'Provider delivery attempts', "
        "'indexes': [models.Index(fields=['status'])]}"
    )
    assert schema_issues(source, "notifications") == []


def test_wrong_app_prefix_is_rejected() -> None:
    source = migration("{'db_table': 'delivery_records', 'db_table_comment': 'Provider delivery attempts'}")
    assert any("prefix" in issue for issue in schema_issues(source, "notifications"))


def test_proxy_models_do_not_create_tables() -> None:
    assert schema_issues(migration("{'proxy': True}"), "notifications") == []


def test_existing_table_alterations_are_outside_the_new_model_guard() -> None:
    assert (
        schema_issues("operations = [migrations.AlterField(model_name='delivery', name='state')]", "notifications")
        == []
    )
