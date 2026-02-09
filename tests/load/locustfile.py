# ===============================================================================
# LOAD TESTING CONFIGURATION FOR PRAHO PLATFORM
# ===============================================================================
"""
Load testing using Locust for PRAHO Platform.

Usage:
    locust -f tests/load/locustfile.py --host=http://localhost:8000

    # Run with specific user count and spawn rate
    locust -f tests/load/locustfile.py --host=http://localhost:8000 --users=100 --spawn-rate=10

    # Run headless
    locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 5m
"""

import random
import string
from locust import HttpUser, task, between, tag


class PRAHOWebUser(HttpUser):
    """Simulates regular web users accessing the platform"""

    wait_time = between(1, 5)  # Wait 1-5 seconds between tasks

    def on_start(self):
        """Login when user starts"""
        self.login()

    def login(self):
        """Authenticate user"""
        # Get CSRF token
        response = self.client.get("/auth/login/")
        if response.status_code == 200:
            # Extract CSRF token from response
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                self.csrf_token = csrf_token
                # Attempt login
                self.client.post("/auth/login/", {
                    "username": "loadtest_user",
                    "password": "LoadTest123!",
                    "csrfmiddlewaretoken": csrf_token,
                })

    def _extract_csrf_token(self, html: str) -> str | None:
        """Extract CSRF token from HTML"""
        import re
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        return match.group(1) if match else None

    @task(10)
    @tag("dashboard")
    def view_dashboard(self):
        """View main dashboard - high frequency"""
        self.client.get("/app/")

    @task(8)
    @tag("customers")
    def list_customers(self):
        """List customers page"""
        self.client.get("/app/customers/")

    @task(5)
    @tag("customers")
    def search_customers(self):
        """Search customers via HTMX"""
        search_terms = ["test", "SRL", "bucuresti", "hosting", "domain"]
        term = random.choice(search_terms)
        self.client.get(
            f"/app/customers/search/?q={term}",
            headers={"HX-Request": "true"}
        )

    @task(6)
    @tag("orders")
    def list_orders(self):
        """List orders page"""
        self.client.get("/app/orders/")

    @task(4)
    @tag("orders")
    def filter_orders(self):
        """Filter orders by status"""
        statuses = ["draft", "pending", "confirmed", "completed"]
        status = random.choice(statuses)
        self.client.get(f"/app/orders/?status={status}")

    @task(7)
    @tag("billing")
    def list_invoices(self):
        """List invoices page"""
        self.client.get("/app/billing/")

    @task(3)
    @tag("billing")
    def view_invoice_pdf(self):
        """View invoice PDF (simulated with random ID)"""
        # This would need actual invoice IDs in production
        pass

    @task(5)
    @tag("products")
    def list_products(self):
        """List products page"""
        self.client.get("/app/products/")

    @task(4)
    @tag("tickets")
    def list_tickets(self):
        """List support tickets"""
        self.client.get("/app/tickets/")


class PRAHOAPIUser(HttpUser):
    """Simulates API users making programmatic requests"""

    wait_time = between(0.5, 2)  # Faster API requests

    @task(10)
    @tag("api")
    def api_customers_list(self):
        """API: List customers"""
        self.client.get(
            "/api/customers/",
            headers={"Accept": "application/json"}
        )

    @task(5)
    @tag("api")
    def api_customer_search(self):
        """API: Search customers"""
        search_terms = ["test", "company", "hosting"]
        term = random.choice(search_terms)
        self.client.get(
            f"/api/customers/?search={term}",
            headers={"Accept": "application/json"}
        )

    @task(8)
    @tag("api")
    def api_orders_list(self):
        """API: List orders"""
        self.client.get(
            "/api/orders/",
            headers={"Accept": "application/json"}
        )

    @task(6)
    @tag("api")
    def api_invoices_list(self):
        """API: List invoices"""
        self.client.get(
            "/api/billing/",
            headers={"Accept": "application/json"}
        )


class PRAHOHeavyUser(HttpUser):
    """Simulates users performing heavy operations"""

    wait_time = between(5, 15)  # Longer wait for heavy operations

    @task(3)
    @tag("heavy", "reports")
    def generate_report(self):
        """Generate analytics report"""
        self.client.get("/app/audit/")

    @task(2)
    @tag("heavy", "export")
    def export_customers(self):
        """Export customers to CSV"""
        self.client.get("/app/customers/export/")

    @task(2)
    @tag("heavy", "pdf")
    def generate_multiple_pdfs(self):
        """Generate multiple invoice PDFs"""
        # Simulated batch PDF generation
        pass


class PRAHOStaffUser(HttpUser):
    """Simulates staff performing administrative tasks"""

    wait_time = between(2, 8)

    def on_start(self):
        """Login as staff"""
        self.login_staff()

    def login_staff(self):
        """Authenticate as staff user"""
        response = self.client.get("/auth/login/")
        if response.status_code == 200:
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                self.client.post("/auth/login/", {
                    "username": "loadtest_staff",
                    "password": "LoadTest123!",
                    "csrfmiddlewaretoken": csrf_token,
                })

    def _extract_csrf_token(self, html: str) -> str | None:
        """Extract CSRF token from HTML"""
        import re
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        return match.group(1) if match else None

    @task(5)
    @tag("admin")
    def view_audit_log(self):
        """View audit log"""
        self.client.get("/app/audit/")

    @task(4)
    @tag("admin")
    def view_system_settings(self):
        """View system settings"""
        self.client.get("/app/settings/")

    @task(3)
    @tag("admin")
    def view_user_management(self):
        """View user management"""
        self.client.get("/users/")

    @task(6)
    @tag("admin", "customers")
    def manage_customers(self):
        """Staff customer management"""
        self.client.get("/app/customers/")

    @task(5)
    @tag("admin", "orders")
    def manage_orders(self):
        """Staff order management"""
        self.client.get("/app/orders/")

    @task(4)
    @tag("admin", "provisioning")
    def view_provisioning(self):
        """View provisioning status"""
        self.client.get("/app/provisioning/")


class PRAHOMixedUser(HttpUser):
    """Simulates realistic mixed usage patterns"""

    wait_time = between(1, 10)

    def on_start(self):
        """Login when user starts"""
        self.login()

    def login(self):
        """Authenticate user"""
        response = self.client.get("/auth/login/")
        if response.status_code == 200:
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                self.client.post("/auth/login/", {
                    "username": "loadtest_user",
                    "password": "LoadTest123!",
                    "csrfmiddlewaretoken": csrf_token,
                })

    def _extract_csrf_token(self, html: str) -> str | None:
        """Extract CSRF token from HTML"""
        import re
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        return match.group(1) if match else None

    @task(20)
    def browse_dashboard(self):
        """Most common: view dashboard"""
        self.client.get("/app/")

    @task(15)
    def browse_customers(self):
        """View customer list"""
        self.client.get("/app/customers/")

    @task(12)
    def browse_orders(self):
        """View order list"""
        self.client.get("/app/orders/")

    @task(10)
    def browse_invoices(self):
        """View invoice list"""
        self.client.get("/app/billing/")

    @task(8)
    def browse_products(self):
        """View product catalog"""
        self.client.get("/app/products/")

    @task(6)
    def browse_tickets(self):
        """View support tickets"""
        self.client.get("/app/tickets/")

    @task(4)
    def search_htmx(self):
        """Perform HTMX search"""
        endpoints = [
            "/app/customers/search/",
            "/app/orders/search/",
        ]
        endpoint = random.choice(endpoints)
        self.client.get(
            f"{endpoint}?q=test",
            headers={"HX-Request": "true"}
        )

    @task(2)
    def view_proformas(self):
        """View proforma invoices"""
        self.client.get("/app/billing/proforma/")

    @task(1)
    def view_domains(self):
        """View domain management"""
        self.client.get("/app/domains/")
