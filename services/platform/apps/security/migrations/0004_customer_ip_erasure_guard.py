"""Bulk observation writes must share the erased customer's root guard."""

from django.db import migrations


def install_guard(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("""
            CREATE FUNCTION security_observation_customer_guard() RETURNS trigger
            LANGUAGE plpgsql AS $$
            DECLARE erased_at timestamptz;
            BEGIN
                SELECT anonymized_at INTO erased_at FROM customers
                    WHERE id = NEW.customer_id FOR NO KEY UPDATE;
                IF erased_at IS NOT NULL THEN
                    RAISE EXCEPTION 'customer_erased' USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END;
            $$;
            CREATE TRIGGER security_observation_customer_erasure
                BEFORE INSERT OR UPDATE ON security_customer_ip_observation
                FOR EACH ROW EXECUTE FUNCTION security_observation_customer_guard();
        """)
    elif schema_editor.connection.vendor == "sqlite":
        schema_editor.execute("""
                CREATE TRIGGER security_observation_customer_erasure_insert
                BEFORE INSERT ON security_customer_ip_observation
                WHEN EXISTS (SELECT 1 FROM customers
                    WHERE id = NEW.customer_id AND anonymized_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'customer_erased'); END;
            """)
        schema_editor.execute("""
                CREATE TRIGGER security_observation_customer_erasure_update
                BEFORE UPDATE ON security_customer_ip_observation
                WHEN EXISTS (SELECT 1 FROM customers
                    WHERE id = NEW.customer_id AND anonymized_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'customer_erased'); END;
            """)


def remove_guard(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("""
            DROP TRIGGER IF EXISTS security_observation_customer_erasure ON security_customer_ip_observation;
            DROP FUNCTION IF EXISTS security_observation_customer_guard();
        """)
    elif schema_editor.connection.vendor == "sqlite":
        schema_editor.execute("DROP TRIGGER IF EXISTS security_observation_customer_erasure_insert")
        schema_editor.execute("DROP TRIGGER IF EXISTS security_observation_customer_erasure_update")


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0008_customer_anonymized_at"),
        ("security", "0003_merge_actions_observations"),
    ]

    operations = [migrations.RunPython(install_guard, remove_guard)]
