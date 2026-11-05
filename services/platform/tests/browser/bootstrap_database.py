"""Create only the fixed, empty browser-test database; never terminate connections."""

import os

import psycopg
from psycopg import sql


def main() -> None:
    assert os.environ.get("HOSTING_CHECKOUT_FULL") == "1"
    assert os.environ.get("DB_NAME") == "hosting_browser"
    assert os.environ.get("DB_HOST") in {"127.0.0.1", "localhost"}
    assert os.environ.get("DB_USER") == "praho_hosting_test"
    with (
        psycopg.connect(
            dbname="postgres",
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            autocommit=True,
        ) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT datname FROM pg_stat_activity WHERE datname IN ('hosting_browser', 'test_hosting_browser')"
        )
        assert not cursor.fetchall(), "An existing browser run still owns database connections"
        cursor.execute(
            "SELECT datname, pg_get_userbyid(datdba) FROM pg_database WHERE datname IN ('hosting_browser', 'test_hosting_browser')"
        )
        owners: dict[str, str] = dict(cursor.fetchall())
        assert all(owner == os.environ["DB_USER"] for owner in owners.values()), "Refusing another owner's database"
        if "hosting_browser" not in owners:
            cursor.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier("hosting_browser"),
                    sql.Identifier(os.environ["DB_USER"]),
                )
            )
    print("Owned hosting_browser database is ready; test_hosting_browser is disposable.")


if __name__ == "__main__":
    main()
