"""
Management command to set up email templates for Romanian hosting provider.
Creates essential templates for billing, provisioning, and customer communication.
"""

from typing import Any

from django.core.management.base import BaseCommand

from apps.notifications.models import EmailTemplate


class Command(BaseCommand):
    help = "Set up essential email templates for Romanian hosting provider"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite existing templates",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Create email templates for Romanian hosting provider"""

        self.stdout.write(self.style.SUCCESS("🏗️ Setting up email templates for PRAHO Platform..."))

        # Email templates to create
        templates = [
            # ===============================================================================
            # BILLING TEMPLATES
            # ===============================================================================
            {
                "key": "invoice_issued",
                "locale": "ro",
                "category": "billing",
                "subject": "Factură nouă #{invoice_number} - PragmaticHost",
                "body_html": """
                <h2>Factură nouă disponibilă</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>A fost emisă o factură nouă pentru serviciile dumneavoastră de hosting:</p>
                <ul>
                    <li><strong>Numărul facturii:</strong> {{invoice_number}}</li>
                    <li><strong>Data emiterii:</strong> {{invoice_date}}</li>
                    <li><strong>Suma totală:</strong> {{total_amount}} {{currency}}</li>
                    <li><strong>Termen de plată:</strong> {{due_date}}</li>
                </ul>
                <p>Puteți vizualiza și descărca factura din contul dumneavoastră client sau folosind linkul de mai jos:</p>
                <p><a href="{{invoice_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Vezi Factura</a></p>
                <p>Mulțumim pentru încrederea acordată!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare pentru factură nouă emisă",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "invoice_date": "Data emiterii facturii",
                    "total_amount": "Suma totală",
                    "currency": "Moneda",
                    "due_date": "Termenul de plată",
                    "invoice_url": "Link către factură",
                },
            },
            {
                "key": "invoice_issued",
                "locale": "en",
                "category": "billing",
                "subject": "New Invoice #{invoice_number} - PragmaticHost",
                "body_html": """
                <h2>New Invoice Available</h2>
                <p>Hello {{customer_name}},</p>
                <p>A new invoice has been issued for your hosting services:</p>
                <ul>
                    <li><strong>Invoice Number:</strong> {{invoice_number}}</li>
                    <li><strong>Issue Date:</strong> {{invoice_date}}</li>
                    <li><strong>Total Amount:</strong> {{total_amount}} {{currency}}</li>
                    <li><strong>Due Date:</strong> {{due_date}}</li>
                </ul>
                <p>You can view and download the invoice from your client area or using the link below:</p>
                <p><a href="{{invoice_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Invoice</a></p>
                <p>Thank you for your business!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Notification for new invoice issued",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "invoice_date": "Invoice issue date",
                    "total_amount": "Total amount",
                    "currency": "Currency",
                    "due_date": "Payment due date",
                    "invoice_url": "Link to invoice",
                },
            },
            # ===============================================================================
            # PAYMENT DUNNING TEMPLATES
            # ===============================================================================
            {
                "key": "payment_reminder",
                "locale": "ro",
                "category": "dunning",
                "subject": "Memento: Factură #{invoice_number} cu scadența apropiată",
                "body_html": """
                <h2>Memento de plată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Vă aducem aminte că factura #{invoice_number} în valoare de {{total_amount}} {{currency}} va ajunge la scadență pe {{due_date}}.</p>
                <p>Pentru a evita întreruperea serviciilor, vă rugăm să efectuați plata cât mai curând posibil.</p>
                <p><a href="{{payment_url}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Plătește Acum</a></p>
                <p>Dacă aveți întrebări, nu ezitați să ne contactați!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Memento pentru factură cu scadența apropiată",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "total_amount": "Suma totală",
                    "currency": "Moneda",
                    "due_date": "Data scadenței",
                    "payment_url": "Link către plată",
                },
            },
            {
                "key": "payment_reminder",
                "locale": "en",
                "category": "dunning",
                "subject": "Reminder: Invoice #{invoice_number} due soon",
                "body_html": """
                <h2>Payment Reminder</h2>
                <p>Hello {{customer_name}},</p>
                <p>This is a friendly reminder that invoice #{invoice_number} for {{total_amount}} {{currency}} is due on {{due_date}}.</p>
                <p>To avoid any service interruption, please make your payment as soon as possible.</p>
                <p><a href="{{payment_url}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Pay Now</a></p>
                <p>If you have any questions, please don't hesitate to contact us!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Reminder for invoice due soon",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "total_amount": "Total amount",
                    "currency": "Currency",
                    "due_date": "Due date",
                    "payment_url": "Payment link",
                },
            },
            {
                "key": "payment_overdue",
                "locale": "ro",
                "category": "dunning",
                "subject": "URGENT: Factură #{invoice_number} restantă - Risc suspendare servicii",
                "body_html": """
                <h2 style="color: #dc3545;">Factură Restantă - Acțiune Urgentă Necesară</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p><strong>Factura #{invoice_number}</strong> în valoare de <strong>{{total_amount}} {{currency}}</strong> este restantă de {{days_overdue}} zile.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p><strong>⚠️ ATENȚIE:</strong> Serviciile dumneavoastră de hosting vor fi suspendate în {{suspension_days}} zile dacă plata nu este efectuată.</p>
                </div>
                <p>Pentru a evita suspendarea serviciilor, vă rugăm să efectuați plata imediat:</p>
                <p><a href="{{payment_url}}" style="background-color: #dc3545; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">PLĂTEȘTE URGENT</a></p>
                <p>Dacă aveți probleme cu plata, contactați-ne imediat la support@pragmatichost.com</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare pentru factură restantă cu risc de suspendare",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "total_amount": "Suma totală",
                    "currency": "Moneda",
                    "days_overdue": "Zile de întârziere",
                    "suspension_days": "Zile până la suspendare",
                    "payment_url": "Link către plată",
                },
            },
            {
                "key": "payment_overdue",
                "locale": "en",
                "category": "dunning",
                "subject": "URGENT: Invoice #{invoice_number} overdue - Service suspension risk",
                "body_html": """
                <h2 style="color: #dc3545;">Overdue Invoice - Urgent Action Required</h2>
                <p>Hello {{customer_name}},</p>
                <p><strong>Invoice #{invoice_number}</strong> for <strong>{{total_amount}} {{currency}}</strong> is {{days_overdue}} days overdue.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p><strong>⚠️ WARNING:</strong> Your hosting services will be suspended in {{suspension_days}} days if payment is not made.</p>
                </div>
                <p>To avoid service suspension, please make payment immediately:</p>
                <p><a href="{{payment_url}}" style="background-color: #dc3545; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">PAY URGENTLY</a></p>
                <p>If you have payment issues, contact us immediately at support@pragmatichost.com</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Notification for overdue invoice with suspension risk",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "total_amount": "Total amount",
                    "currency": "Currency",
                    "days_overdue": "Days overdue",
                    "suspension_days": "Days until suspension",
                    "payment_url": "Payment link",
                },
            },
            # ===============================================================================
            # PROVISIONING TEMPLATES
            # ===============================================================================
            {
                "key": "service_activated",
                "locale": "ro",
                "category": "provisioning",
                "subject": "Serviciul {{service_name}} a fost activat - Detalii de acces",
                "body_html": """
                <h2>🎉 Serviciul dumneavoastră a fost activat!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Serviciul <strong>{{service_name}}</strong> a fost configurat cu succes și este acum activ!</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>Detalii de acces:</h3>
                    <ul>
                        <li><strong>Serviciu:</strong> {{service_name}}</li>
                        <li><strong>Domeniu principal:</strong> {{primary_domain}}</li>
                        <li><strong>Panel de control:</strong> <a href="{{control_panel_url}}">{{control_panel_url}}</a></li>
                        <li><strong>Username:</strong> {{username}}</li>
                        <li><strong>Server:</strong> {{server_name}}</li>
                    </ul>
                </div>
                <p>Datele de autentificare au fost trimise separat pentru securitate.</p>
                <p>Pentru suport tehnic, contactați-ne la support@pragmatichost.com</p>
                <p>Bun venit în familia PragmaticHost!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare pentru serviciu nou activat",
                "variables": {
                    "customer_name": "Numele clientului",
                    "service_name": "Numele serviciului",
                    "primary_domain": "Domeniul principal",
                    "control_panel_url": "URL panel de control",
                    "username": "Numele de utilizator",
                    "server_name": "Numele serverului",
                },
            },
            {
                "key": "service_activated",
                "locale": "en",
                "category": "provisioning",
                "subject": "Service {{service_name}} has been activated - Access details",
                "body_html": """
                <h2>🎉 Your service has been activated!</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your <strong>{{service_name}}</strong> service has been successfully configured and is now active!</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>Access Details:</h3>
                    <ul>
                        <li><strong>Service:</strong> {{service_name}}</li>
                        <li><strong>Primary Domain:</strong> {{primary_domain}}</li>
                        <li><strong>Control Panel:</strong> <a href="{{control_panel_url}}">{{control_panel_url}}</a></li>
                        <li><strong>Username:</strong> {{username}}</li>
                        <li><strong>Server:</strong> {{server_name}}</li>
                    </ul>
                </div>
                <p>Login credentials have been sent separately for security.</p>
                <p>For technical support, contact us at support@pragmatichost.com</p>
                <p>Welcome to the PragmaticHost family!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Notification for newly activated service",
                "variables": {
                    "customer_name": "Customer name",
                    "service_name": "Service name",
                    "primary_domain": "Primary domain",
                    "control_panel_url": "Control panel URL",
                    "username": "Username",
                    "server_name": "Server name",
                },
            },
            # ===============================================================================
            # SUPPORT TEMPLATES
            # ===============================================================================
            {
                "key": "ticket_created",
                "locale": "ro",
                "category": "support",
                "subject": "Ticket nou #{ticket_number}: {{ticket_subject}}",
                "body_html": """
                <h2>Ticket de suport creat</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Ticketul dumneavoastră de suport a fost înregistrat cu succes:</p>
                <ul>
                    <li><strong>Numărul ticket:</strong> #{{ticket_number}}</li>
                    <li><strong>Subiect:</strong> {{ticket_subject}}</li>
                    <li><strong>Prioritate:</strong> {{priority}}</li>
                    <li><strong>Departament:</strong> {{department}}</li>
                </ul>
                <p>Echipa noastră de suport va răspunde în maximum {{sla_response}} ore.</p>
                <p><a href="{{ticket_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Vezi Ticket</a></p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare pentru ticket nou creat",
                "variables": {
                    "customer_name": "Numele clientului",
                    "ticket_number": "Numărul ticket",
                    "ticket_subject": "Subiectul ticket",
                    "priority": "Prioritatea",
                    "department": "Departamentul",
                    "sla_response": "Timpul de răspuns SLA",
                    "ticket_url": "Link către ticket",
                },
            },
            {
                "key": "ticket_created",
                "locale": "en",
                "category": "support",
                "subject": "New ticket #{ticket_number}: {{ticket_subject}}",
                "body_html": """
                <h2>Support Ticket Created</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your support ticket has been successfully registered:</p>
                <ul>
                    <li><strong>Ticket Number:</strong> #{{ticket_number}}</li>
                    <li><strong>Subject:</strong> {{ticket_subject}}</li>
                    <li><strong>Priority:</strong> {{priority}}</li>
                    <li><strong>Department:</strong> {{department}}</li>
                </ul>
                <p>Our support team will respond within {{sla_response}} hours.</p>
                <p><a href="{{ticket_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Ticket</a></p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Confirmation for new ticket created",
                "variables": {
                    "customer_name": "Customer name",
                    "ticket_number": "Ticket number",
                    "ticket_subject": "Ticket subject",
                    "priority": "Priority",
                    "department": "Department",
                    "sla_response": "SLA response time",
                    "ticket_url": "Ticket link",
                },
            },
            # ===============================================================================
            # ORDER TEMPLATES
            # ===============================================================================
            {
                "key": "order_placed",
                "locale": "ro",
                "category": "billing",
                "subject": "Comandă nouă #{order_number} confirmată - PragmaticHost",
                "body_html": """
                <h2>🛒 Comanda dumneavoastră a fost confirmată!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Mulțumim pentru comandă! Comanda dumneavoastră a fost înregistrată cu succes:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <h3>📋 Detalii comandă:</h3>
                    <ul>
                        <li><strong>Numărul comenzii:</strong> #{{order_number}}</li>
                        <li><strong>Data comenzii:</strong> {{order_date}}</li>
                        <li><strong>Status:</strong> {{order_status}}</li>
                        <li><strong>Total:</strong> {{total_amount}} {{currency}}</li>
                    </ul>
                </div>
                <h3>📦 Produse comandate:</h3>
                {{order_items}}
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>🚀 Ce urmează:</h3>
                    <ol>
                        <li>Veți primi factura proforma pentru aprobare</li>
                        <li>După plată, serviciile vor fi activate automat</li>
                        <li>Veți primi detaliile de acces pe email</li>
                    </ol>
                </div>
                <p><a href="{{order_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Vezi Comanda</a></p>
                <p>Pentru întrebări, contactați-ne la comenzi@pragmatichost.com</p>
                <p>Mulțumim că ați ales PragmaticHost!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare pentru comandă nouă plasată",
                "variables": {
                    "customer_name": "Numele clientului",
                    "order_number": "Numărul comenzii",
                    "order_date": "Data comenzii",
                    "order_status": "Status comandă",
                    "total_amount": "Suma totală",
                    "currency": "Moneda",
                    "order_items": "Lista produselor comandate",
                    "order_url": "Link către comandă",
                },
            },
            {
                "key": "order_placed",
                "locale": "en",
                "category": "billing",
                "subject": "New order #{order_number} confirmed - PragmaticHost",
                "body_html": """
                <h2>🛒 Your order has been confirmed!</h2>
                <p>Hello {{customer_name}},</p>
                <p>Thank you for your order! Your order has been successfully registered:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <h3>📋 Order Details:</h3>
                    <ul>
                        <li><strong>Order Number:</strong> #{{order_number}}</li>
                        <li><strong>Order Date:</strong> {{order_date}}</li>
                        <li><strong>Status:</strong> {{order_status}}</li>
                        <li><strong>Total:</strong> {{total_amount}} {{currency}}</li>
                    </ul>
                </div>
                <h3>📦 Ordered Products:</h3>
                {{order_items}}
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>🚀 What's Next:</h3>
                    <ol>
                        <li>You will receive a proforma invoice for approval</li>
                        <li>After payment, services will be activated automatically</li>
                        <li>You will receive access details via email</li>
                    </ol>
                </div>
                <p><a href="{{order_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Order</a></p>
                <p>For questions, contact us at orders@pragmatichost.com</p>
                <p>Thank you for choosing PragmaticHost!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Confirmation for new order placed",
                "variables": {
                    "customer_name": "Customer name",
                    "order_number": "Order number",
                    "order_date": "Order date",
                    "order_status": "Order status",
                    "total_amount": "Total amount",
                    "currency": "Currency",
                    "order_items": "List of ordered products",
                    "order_url": "Order link",
                },
            },
            # ===============================================================================
            # WELCOME TEMPLATES
            # ===============================================================================
            {
                "key": "customer_welcome",
                "locale": "ro",
                "category": "welcome",
                "subject": "Bun venit la PragmaticHost! Contul dumneavoastră a fost creat",
                "body_html": """
                <h2>🎉 Bun venit în familia PragmaticHost!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Mulțumim că ați ales PragmaticHost pentru nevoile dumneavoastră de hosting!</p>
                <p>Contul dumneavoastră client a fost creat cu succes. Iată ce urmează:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <h3>🚀 Pașii următori:</h3>
                    <ol>
                        <li>Conectați-vă în zona client: <a href="{{client_area_url}}">{{client_area_url}}</a></li>
                        <li>Completați profilul companiei pentru facturare</li>
                        <li>Comandați serviciile de hosting dorite</li>
                        <li>Configurați domeniile și site-urile web</li>
                    </ol>
                </div>
                <p>Pentru întrebări sau asistență, contactați-ne:</p>
                <ul>
                    <li>📧 Email: support@pragmatichost.com</li>
                    <li>📞 Telefon: +40 XXX XXX XXX</li>
                    <li>💬 Chat live din zona client</li>
                </ul>
                <p>Bun venit în familia PragmaticHost!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Email de bun venit pentru clienți noi",
                "variables": {"customer_name": "Numele clientului", "client_area_url": "URL zona client"},
            },
            {
                "key": "customer_welcome",
                "locale": "en",
                "category": "welcome",
                "subject": "Welcome to PragmaticHost! Your account has been created",
                "body_html": """
                <h2>🎉 Welcome to the PragmaticHost family!</h2>
                <p>Hello {{customer_name}},</p>
                <p>Thank you for choosing PragmaticHost for your hosting needs!</p>
                <p>Your client account has been successfully created. Here's what's next:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <h3>🚀 Next Steps:</h3>
                    <ol>
                        <li>Log in to your client area: <a href="{{client_area_url}}">{{client_area_url}}</a></li>
                        <li>Complete your company profile for billing</li>
                        <li>Order your desired hosting services</li>
                        <li>Configure your domains and websites</li>
                    </ol>
                </div>
                <p>For questions or assistance, contact us:</p>
                <ul>
                    <li>📧 Email: support@pragmatichost.com</li>
                    <li>📞 Phone: +40 XXX XXX XXX</li>
                    <li>💬 Live chat from client area</li>
                </ul>
                <p>Welcome to the PragmaticHost family!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Welcome email for new customers",
                "variables": {"customer_name": "Customer name", "client_area_url": "Client area URL"},
            },
        ]

        created_count = 0
        updated_count = 0

        for template_data in templates:
            key = template_data["key"]
            locale = template_data["locale"]

            # Check if template already exists
            try:
                template = EmailTemplate.objects.get(key=key, locale=locale)
                if options["overwrite"]:
                    # Update existing template
                    for field, value in template_data.items():
                        setattr(template, field, value)
                    template.version += 1  # Increment version
                    template.save()
                    updated_count += 1
                    self.stdout.write(f"📝 Updated: {key} ({locale})")
                else:
                    self.stdout.write(f"⏭️  Skipped: {key} ({locale}) - already exists")
            except EmailTemplate.DoesNotExist:
                # Create new template
                EmailTemplate.objects.create(**template_data)
                created_count += 1
                self.stdout.write(f"✅ Created: {key} ({locale})")

        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f"\n🎯 Email template setup complete!\n"
                f"✅ Created: {created_count} new templates\n"
                f"📝 Updated: {updated_count} existing templates\n"
                f"📧 Total templates: {EmailTemplate.objects.count()}"
            )
        )

        # Show template categories
        categories = EmailTemplate.objects.values_list("category", flat=True).distinct()
        self.stdout.write(f"\n📂 Available categories: {', '.join(categories)}")

        self.stdout.write(
            self.style.WARNING(
                "\n💡 Next steps:\n"
                "1. Review templates in Django admin\n"
                "2. Customize content for your business\n"
                "3. Test email sending functionality\n"
                "4. Configure email service provider (SMTP/SendGrid/etc.)"
            )
        )
