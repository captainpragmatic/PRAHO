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
            # ===============================================================================
            # PAYMENT TEMPLATES
            # ===============================================================================
            {
                "key": "payment_success",
                "locale": "ro",
                "category": "billing",
                "subject": "Plata a fost procesată cu succes - PragmaticHost",
                "body_html": """
                <h2>✅ Plata dumneavoastră a fost procesată!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Confirmăm primirea plății pentru factura <strong>{{invoice_number}}</strong>.</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>💳 Detalii plată:</h3>
                    <ul>
                        <li><strong>Sumă:</strong> {{payment_amount}} {{currency}}</li>
                        <li><strong>Factură:</strong> {{invoice_number}}</li>
                        <li><strong>Metodă:</strong> {{payment_method}}</li>
                    </ul>
                </div>
                <p>Mulțumim pentru plată!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare plată procesată cu succes",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "payment_amount": "Suma plătită",
                    "currency": "Moneda",
                    "payment_method": "Metoda de plată",
                },
            },
            {
                "key": "payment_success",
                "locale": "en",
                "category": "billing",
                "subject": "Payment processed successfully - PragmaticHost",
                "body_html": """
                <h2>✅ Your payment has been processed!</h2>
                <p>Hello {{customer_name}},</p>
                <p>We confirm receipt of your payment for invoice <strong>{{invoice_number}}</strong>.</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <h3>💳 Payment Details:</h3>
                    <ul>
                        <li><strong>Amount:</strong> {{payment_amount}} {{currency}}</li>
                        <li><strong>Invoice:</strong> {{invoice_number}}</li>
                        <li><strong>Method:</strong> {{payment_method}}</li>
                    </ul>
                </div>
                <p>Thank you for your payment!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Payment processed successfully confirmation",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "payment_amount": "Payment amount",
                    "currency": "Currency",
                    "payment_method": "Payment method",
                },
            },
            {
                "key": "payment_failed",
                "locale": "ro",
                "category": "billing",
                "subject": "⚠️ Plata nu a putut fi procesată - PragmaticHost",
                "body_html": """
                <h2>⚠️ Plata nu a putut fi procesată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Din păcate, plata dumneavoastră pentru factura <strong>{{invoice_number}}</strong> nu a putut fi procesată.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <h3>Ce puteți face:</h3>
                    <ol>
                        <li>Verificați datele cardului sau metoda de plată</li>
                        <li>Asigurați-vă că aveți fonduri suficiente</li>
                        <li>Încercați din nou din zona client</li>
                    </ol>
                </div>
                <p>Dacă problema persistă, contactați-ne la billing@pragmatichost.com</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare plată eșuată",
                "variables": {"customer_name": "Numele clientului", "invoice_number": "Numărul facturii"},
            },
            {
                "key": "payment_failed",
                "locale": "en",
                "category": "billing",
                "subject": "⚠️ Payment could not be processed - PragmaticHost",
                "body_html": """
                <h2>⚠️ Payment could not be processed</h2>
                <p>Hello {{customer_name}},</p>
                <p>Unfortunately, your payment for invoice <strong>{{invoice_number}}</strong> could not be processed.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <h3>What you can do:</h3>
                    <ol>
                        <li>Check your card details or payment method</li>
                        <li>Ensure you have sufficient funds</li>
                        <li>Try again from your client area</li>
                    </ol>
                </div>
                <p>If the issue persists, contact us at billing@pragmatichost.com</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Payment failed notification",
                "variables": {"customer_name": "Customer name", "invoice_number": "Invoice number"},
            },
            {
                "key": "payment_refund",
                "locale": "ro",
                "category": "billing",
                "subject": "Rambursare procesată - PragmaticHost",
                "body_html": """
                <h2>💰 Rambursarea a fost procesată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Rambursarea pentru factura <strong>{{invoice_number}}</strong> a fost procesată.</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <p><strong>Sumă rambursată:</strong> {{refund_amount}} {{currency}}</p>
                </div>
                <p>Suma va fi returnată în contul dumneavoastră în 5-10 zile lucrătoare.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare rambursare plată",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "refund_amount": "Suma rambursată",
                    "currency": "Moneda",
                },
            },
            {
                "key": "payment_refund",
                "locale": "en",
                "category": "billing",
                "subject": "Refund processed - PragmaticHost",
                "body_html": """
                <h2>💰 Your refund has been processed</h2>
                <p>Hello {{customer_name}},</p>
                <p>The refund for invoice <strong>{{invoice_number}}</strong> has been processed.</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <p><strong>Refund amount:</strong> {{refund_amount}} {{currency}}</p>
                </div>
                <p>The amount will be returned to your account within 5-10 business days.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Payment refund confirmation",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "refund_amount": "Refund amount",
                    "currency": "Currency",
                },
            },
            {
                "key": "invoice_refund_confirmation",
                "locale": "ro",
                "category": "billing",
                "subject": "Factura {{invoice_number}} - rambursare confirmată - PragmaticHost",
                "body_html": """
                <h2>✅ Rambursarea facturii a fost confirmată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Factura <strong>{{invoice_number}}</strong> a fost rambursată integral.</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <p><strong>Sumă rambursată:</strong> {{refund_amount}} {{currency}}</p>
                </div>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare rambursare factură",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "refund_amount": "Suma rambursată",
                    "currency": "Moneda",
                },
            },
            {
                "key": "invoice_refund_confirmation",
                "locale": "en",
                "category": "billing",
                "subject": "Invoice {{invoice_number}} - refund confirmed - PragmaticHost",
                "body_html": """
                <h2>✅ Invoice refund confirmed</h2>
                <p>Hello {{customer_name}},</p>
                <p>Invoice <strong>{{invoice_number}}</strong> has been fully refunded.</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <p><strong>Refund amount:</strong> {{refund_amount}} {{currency}}</p>
                </div>
                <p>PragmaticHost Team</p>
                """,
                "description": "Invoice refund confirmation",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "refund_amount": "Refund amount",
                    "currency": "Currency",
                },
            },
            {
                "key": "payment_retry_success",
                "locale": "ro",
                "category": "billing",
                "subject": "✅ Plata a fost procesată la a doua încercare - PragmaticHost",
                "body_html": """
                <h2>✅ Plata a fost procesată cu succes!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Vă informăm că plata dumneavoastră a fost procesată cu succes la reîncercare.</p>
                <p>Serviciile asociate sunt acum active.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare plată reușită la reîncercare",
                "variables": {"customer_name": "Numele clientului"},
            },
            {
                "key": "payment_retry_success",
                "locale": "en",
                "category": "billing",
                "subject": "✅ Payment processed on retry - PragmaticHost",
                "body_html": """
                <h2>✅ Payment processed successfully!</h2>
                <p>Hello {{customer_name}},</p>
                <p>We're happy to let you know that your payment was successfully processed on retry.</p>
                <p>Your associated services are now active.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Payment retry success confirmation",
                "variables": {"customer_name": "Customer name"},
            },
            # ===============================================================================
            # INTERNAL ALERT TEMPLATES
            # ===============================================================================
            {
                "key": "finance_large_refund_alert",
                "locale": "ro",
                "category": "internal",
                "subject": "🚨 Alertă: Rambursare mare - Factura {{invoice_number}}",
                "body_html": """
                <h2>🚨 Alertă rambursare mare</h2>
                <p>O rambursare ce depășește pragul de <strong>{{threshold}} EUR</strong> a fost procesată:</p>
                <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 15px 0;">
                    <ul>
                        <li><strong>Factură:</strong> {{invoice_number}}</li>
                        <li><strong>Client:</strong> {{customer_name}}</li>
                        <li><strong>Sumă:</strong> {{refund_amount}} {{currency}}</li>
                    </ul>
                </div>
                <p>Verificați tranzacția în panoul de administrare.</p>
                """,
                "description": "Alertă internă pentru rambursări mari",
                "variables": {
                    "invoice_number": "Numărul facturii",
                    "customer_name": "Numele clientului",
                    "refund_amount": "Suma rambursată",
                    "currency": "Moneda",
                    "threshold": "Pragul de alertă",
                },
            },
            {
                "key": "finance_large_refund_alert",
                "locale": "en",
                "category": "internal",
                "subject": "🚨 Alert: Large refund - Invoice {{invoice_number}}",
                "body_html": """
                <h2>🚨 Large Refund Alert</h2>
                <p>A refund exceeding the <strong>{{threshold}} EUR</strong> threshold has been processed:</p>
                <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 15px 0;">
                    <ul>
                        <li><strong>Invoice:</strong> {{invoice_number}}</li>
                        <li><strong>Customer:</strong> {{customer_name}}</li>
                        <li><strong>Amount:</strong> {{refund_amount}} {{currency}}</li>
                    </ul>
                </div>
                <p>Please review the transaction in the admin panel.</p>
                """,
                "description": "Internal alert for large refunds",
                "variables": {
                    "invoice_number": "Invoice number",
                    "customer_name": "Customer name",
                    "refund_amount": "Refund amount",
                    "currency": "Currency",
                    "threshold": "Alert threshold",
                },
            },
            # ===============================================================================
            # GRANDFATHERING TEMPLATES
            # ===============================================================================
            {
                "key": "grandfathering_expiring",
                "locale": "ro",
                "category": "billing",
                "subject": "Prețul special pentru {{product_name}} expiră curând - PragmaticHost",
                "body_html": """
                <h2>⏰ Prețul dumneavoastră special expiră curând</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Vă informăm că prețul preferențial de <strong>{{locked_price}} {{currency}}</strong>
                   pentru <strong>{{product_name}}</strong> expiră la <strong>{{expires_at}}</strong>.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>Economisiți <strong>{{savings_percent}}%</strong> față de prețul standard.
                       Reînnoiți înainte de expirare pentru a păstra acest preț!</p>
                </div>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare expirare preț grandfathered",
                "variables": {
                    "customer_name": "Numele clientului",
                    "product_name": "Numele produsului",
                    "locked_price": "Prețul blocat",
                    "currency": "Moneda",
                    "expires_at": "Data expirării",
                    "savings_percent": "Procentul de economisire",
                },
            },
            {
                "key": "grandfathering_expiring",
                "locale": "en",
                "category": "billing",
                "subject": "Your special price for {{product_name}} expires soon - PragmaticHost",
                "body_html": """
                <h2>⏰ Your special price expires soon</h2>
                <p>Hello {{customer_name}},</p>
                <p>This is a reminder that your grandfathered price of <strong>{{locked_price}} {{currency}}</strong>
                   for <strong>{{product_name}}</strong> expires on <strong>{{expires_at}}</strong>.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>You're saving <strong>{{savings_percent}}%</strong> compared to the standard price.
                       Renew before expiry to keep this rate!</p>
                </div>
                <p>PragmaticHost Team</p>
                """,
                "description": "Grandfathered price expiring notification",
                "variables": {
                    "customer_name": "Customer name",
                    "product_name": "Product name",
                    "locked_price": "Locked price",
                    "currency": "Currency",
                    "expires_at": "Expiry date",
                    "savings_percent": "Savings percentage",
                },
            },
            # ===============================================================================
            # INVOICE LIFECYCLE TEMPLATES
            # ===============================================================================
            {
                "key": "invoice_created",
                "locale": "ro",
                "category": "billing",
                "subject": "Factură nouă {{invoice_number}} - PragmaticHost",
                "body_html": """
                <h2>📋 Factură nouă creată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>O factură nouă a fost creată pentru contul dumneavoastră:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <ul>
                        <li><strong>Număr factură:</strong> {{invoice_number}}</li>
                        <li><strong>Sumă:</strong> {{total_amount}} {{currency}}</li>
                        <li><strong>Scadență:</strong> {{due_date}}</li>
                    </ul>
                </div>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare factură creată",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "total_amount": "Suma totală",
                    "currency": "Moneda",
                    "due_date": "Data scadenței",
                },
            },
            {
                "key": "invoice_created",
                "locale": "en",
                "category": "billing",
                "subject": "New invoice {{invoice_number}} - PragmaticHost",
                "body_html": """
                <h2>📋 New invoice created</h2>
                <p>Hello {{customer_name}},</p>
                <p>A new invoice has been created for your account:</p>
                <div style="background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0;">
                    <ul>
                        <li><strong>Invoice number:</strong> {{invoice_number}}</li>
                        <li><strong>Amount:</strong> {{total_amount}} {{currency}}</li>
                        <li><strong>Due date:</strong> {{due_date}}</li>
                    </ul>
                </div>
                <p>PragmaticHost Team</p>
                """,
                "description": "Invoice created notification",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "total_amount": "Total amount",
                    "currency": "Currency",
                    "due_date": "Due date",
                },
            },
            {
                "key": "payment_received",
                "locale": "ro",
                "category": "billing",
                "subject": "Plată primită pentru factura {{invoice_number}} - PragmaticHost",
                "body_html": """
                <h2>✅ Plata a fost primită</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Am primit plata pentru factura <strong>{{invoice_number}}</strong>. Mulțumim!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare plată primită pentru factură",
                "variables": {"customer_name": "Numele clientului", "invoice_number": "Numărul facturii"},
            },
            {
                "key": "payment_received",
                "locale": "en",
                "category": "billing",
                "subject": "Payment received for invoice {{invoice_number}} - PragmaticHost",
                "body_html": """
                <h2>✅ Payment received</h2>
                <p>Hello {{customer_name}},</p>
                <p>We've received your payment for invoice <strong>{{invoice_number}}</strong>. Thank you!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Payment received for invoice confirmation",
                "variables": {"customer_name": "Customer name", "invoice_number": "Invoice number"},
            },
            {
                "key": "invoice_overdue",
                "locale": "ro",
                "category": "billing",
                "subject": "⚠️ Factura {{invoice_number}} este restantă - PragmaticHost",
                "body_html": """
                <h2>⚠️ Factură restantă</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Factura <strong>{{invoice_number}}</strong> este restantă de <strong>{{days_overdue}} zile</strong>.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>Vă rugăm să efectuați plata cât mai curând posibil pentru a evita suspendarea serviciilor.</p>
                </div>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare factură restantă",
                "variables": {
                    "customer_name": "Numele clientului",
                    "invoice_number": "Numărul facturii",
                    "days_overdue": "Zile de întârziere",
                },
            },
            {
                "key": "invoice_overdue",
                "locale": "en",
                "category": "billing",
                "subject": "⚠️ Invoice {{invoice_number}} is overdue - PragmaticHost",
                "body_html": """
                <h2>⚠️ Invoice overdue</h2>
                <p>Hello {{customer_name}},</p>
                <p>Invoice <strong>{{invoice_number}}</strong> is <strong>{{days_overdue}} days</strong> overdue.</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>Please make payment as soon as possible to avoid service suspension.</p>
                </div>
                <p>PragmaticHost Team</p>
                """,
                "description": "Invoice overdue notification",
                "variables": {
                    "customer_name": "Customer name",
                    "invoice_number": "Invoice number",
                    "days_overdue": "Days overdue",
                },
            },
            {
                "key": "invoice_voided",
                "locale": "ro",
                "category": "billing",
                "subject": "Factura {{invoice_number}} a fost anulată - PragmaticHost",
                "body_html": """
                <h2>🚫 Factură anulată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Factura <strong>{{invoice_number}}</strong> a fost anulată.</p>
                <p>Dacă aveți întrebări, contactați-ne la billing@pragmatichost.com</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare factură anulată",
                "variables": {"customer_name": "Numele clientului", "invoice_number": "Numărul facturii"},
            },
            {
                "key": "invoice_voided",
                "locale": "en",
                "category": "billing",
                "subject": "Invoice {{invoice_number}} has been voided - PragmaticHost",
                "body_html": """
                <h2>🚫 Invoice voided</h2>
                <p>Hello {{customer_name}},</p>
                <p>Invoice <strong>{{invoice_number}}</strong> has been voided.</p>
                <p>If you have questions, contact us at billing@pragmatichost.com</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Invoice voided notification",
                "variables": {"customer_name": "Customer name", "invoice_number": "Invoice number"},
            },
            # ===============================================================================
            # ORDER LIFECYCLE TEMPLATES
            # ===============================================================================
            {
                "key": "order_cancelled",
                "locale": "ro",
                "category": "billing",
                "subject": "Comanda #{{order_number}} a fost anulată - PragmaticHost",
                "body_html": """
                <h2>🚫 Comandă anulată</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Comanda dumneavoastră <strong>#{{order_number}}</strong> a fost anulată.</p>
                <p>Dacă nu ați solicitat această anulare, contactați-ne imediat.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare comandă anulată",
                "variables": {"customer_name": "Numele clientului", "order_number": "Numărul comenzii"},
            },
            {
                "key": "order_cancelled",
                "locale": "en",
                "category": "billing",
                "subject": "Order #{{order_number}} has been cancelled - PragmaticHost",
                "body_html": """
                <h2>🚫 Order cancelled</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your order <strong>#{{order_number}}</strong> has been cancelled.</p>
                <p>If you did not request this cancellation, please contact us immediately.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Order cancelled notification",
                "variables": {"customer_name": "Customer name", "order_number": "Order number"},
            },
            # ===============================================================================
            # PROVISIONING TEMPLATES
            # ===============================================================================
            {
                "key": "service_ready",
                "locale": "ro",
                "category": "provisioning",
                "subject": "🚀 Serviciul dumneavoastră este activ! - PragmaticHost",
                "body_html": """
                <h2>🚀 Serviciul este gata de utilizare!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Serviciul comandat a fost activat cu succes:</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <ul>
                        <li><strong>Serviciu:</strong> {{service_name}}</li>
                        <li><strong>Comandă:</strong> #{{order_number}}</li>
                    </ul>
                </div>
                <p>Puteți gestiona serviciul din zona client.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare serviciu activat și gata de utilizare",
                "variables": {
                    "customer_name": "Numele clientului",
                    "service_name": "Numele serviciului",
                    "order_number": "Numărul comenzii",
                },
            },
            {
                "key": "service_ready",
                "locale": "en",
                "category": "provisioning",
                "subject": "🚀 Your service is active! - PragmaticHost",
                "body_html": """
                <h2>🚀 Your service is ready to use!</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your ordered service has been successfully activated:</p>
                <div style="background-color: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 15px 0;">
                    <ul>
                        <li><strong>Service:</strong> {{service_name}}</li>
                        <li><strong>Order:</strong> #{{order_number}}</li>
                    </ul>
                </div>
                <p>You can manage your service from the client area.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Service activated and ready notification",
                "variables": {
                    "customer_name": "Customer name",
                    "service_name": "Service name",
                    "order_number": "Order number",
                },
            },
            {
                "key": "provisioning_failed",
                "locale": "ro",
                "category": "provisioning",
                "subject": "⚠️ Activarea serviciului a eșuat - PragmaticHost",
                "body_html": """
                <h2>⚠️ Activarea serviciului a eșuat</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Din păcate, activarea serviciului din comanda <strong>#{{order_number}}</strong> a întâmpinat o problemă.</p>
                <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 15px 0;">
                    <p>Echipa noastră tehnică a fost notificată și lucrează la rezolvarea problemei.
                       Veți fi contactat(ă) în cel mai scurt timp.</p>
                </div>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare eșec activare serviciu",
                "variables": {"customer_name": "Numele clientului", "order_number": "Numărul comenzii"},
            },
            {
                "key": "provisioning_failed",
                "locale": "en",
                "category": "provisioning",
                "subject": "⚠️ Service activation failed - PragmaticHost",
                "body_html": """
                <h2>⚠️ Service activation failed</h2>
                <p>Hello {{customer_name}},</p>
                <p>Unfortunately, the service activation for order <strong>#{{order_number}}</strong> encountered an issue.</p>
                <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 15px 0;">
                    <p>Our technical team has been notified and is working on resolving the issue.
                       You will be contacted shortly.</p>
                </div>
                <p>PragmaticHost Team</p>
                """,
                "description": "Service provisioning failed notification",
                "variables": {"customer_name": "Customer name", "order_number": "Order number"},
            },
            {
                "key": "order_completed",
                "locale": "ro",
                "category": "billing",
                "subject": "Comanda #{{order_number}} a fost finalizată - PragmaticHost",
                "body_html": """
                <h2>✅ Comanda dumneavoastră a fost finalizată!</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Comanda <strong>#{{order_number}}</strong> a fost procesată complet.
                   Toate serviciile comandate sunt acum active.</p>
                <p>Puteți gestiona serviciile din zona client.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare comandă finalizată",
                "variables": {"customer_name": "Numele clientului", "order_number": "Numărul comenzii"},
            },
            {
                "key": "order_completed",
                "locale": "en",
                "category": "billing",
                "subject": "Order #{{order_number}} completed - PragmaticHost",
                "body_html": """
                <h2>✅ Your order has been completed!</h2>
                <p>Hello {{customer_name}},</p>
                <p>Order <strong>#{{order_number}}</strong> has been fully processed.
                   All ordered services are now active.</p>
                <p>You can manage your services from the client area.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Order completed notification",
                "variables": {"customer_name": "Customer name", "order_number": "Order number"},
            },
            # ===============================================================================
            # INTERNAL NOTIFICATION TEMPLATES
            # ===============================================================================
            {
                "key": "important_customer_note",
                "locale": "ro",
                "category": "internal",
                "subject": "📌 Notă importantă client: {{customer_name}}",
                "body_html": """
                <h2>📌 Notă importantă de la client</h2>
                <p>O notă marcată ca importantă a fost adăugată pentru clientul <strong>{{customer_name}}</strong>:</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>{{note_content}}</p>
                </div>
                <p>Verificați detaliile în panoul de administrare.</p>
                """,
                "description": "Alertă internă pentru note importante client",
                "variables": {"customer_name": "Numele clientului", "note_content": "Conținutul notei"},
            },
            {
                "key": "important_customer_note",
                "locale": "en",
                "category": "internal",
                "subject": "📌 Important customer note: {{customer_name}}",
                "body_html": """
                <h2>📌 Important Customer Note</h2>
                <p>A note marked as important has been added for customer <strong>{{customer_name}}</strong>:</p>
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0;">
                    <p>{{note_content}}</p>
                </div>
                <p>Check the details in the admin panel.</p>
                """,
                "description": "Internal alert for important customer notes",
                "variables": {"customer_name": "Customer name", "note_content": "Note content"},
            },
            # ===============================================================================
            # CUSTOMER LIFECYCLE TEMPLATES
            # ===============================================================================
            {
                "key": "customer_activated",
                "locale": "ro",
                "category": "welcome",
                "subject": "Contul dumneavoastră a fost activat - PragmaticHost",
                "body_html": """
                <h2>✅ Cont activat</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Contul dumneavoastră PragmaticHost a fost activat cu succes. Puteți comanda servicii de hosting!</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Confirmare activare cont client",
                "variables": {"customer_name": "Numele clientului"},
            },
            {
                "key": "customer_activated",
                "locale": "en",
                "category": "welcome",
                "subject": "Your account has been activated - PragmaticHost",
                "body_html": """
                <h2>✅ Account activated</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your PragmaticHost account has been successfully activated. You can now order hosting services!</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Customer account activation confirmation",
                "variables": {"customer_name": "Customer name"},
            },
            {
                "key": "customer_suspended",
                "locale": "ro",
                "category": "billing",
                "subject": "⚠️ Contul dumneavoastră a fost suspendat - PragmaticHost",
                "body_html": """
                <h2>⚠️ Cont suspendat</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Contul dumneavoastră PragmaticHost a fost suspendat.</p>
                <p>Contactați-ne la billing@pragmatichost.com pentru detalii și reactivare.</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare suspendare cont client",
                "variables": {"customer_name": "Numele clientului"},
            },
            {
                "key": "customer_suspended",
                "locale": "en",
                "category": "billing",
                "subject": "⚠️ Your account has been suspended - PragmaticHost",
                "body_html": """
                <h2>⚠️ Account suspended</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your PragmaticHost account has been suspended.</p>
                <p>Contact us at billing@pragmatichost.com for details and reactivation.</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Customer account suspension notification",
                "variables": {"customer_name": "Customer name"},
            },
            {
                "key": "customer_deactivated",
                "locale": "ro",
                "category": "billing",
                "subject": "Contul dumneavoastră a fost dezactivat - PragmaticHost",
                "body_html": """
                <h2>🚫 Cont dezactivat</h2>
                <p>Bună ziua {{customer_name}},</p>
                <p>Contul dumneavoastră PragmaticHost a fost dezactivat.</p>
                <p>Dacă doriți reactivarea, contactați-ne la support@pragmatichost.com</p>
                <p>Echipa PragmaticHost</p>
                """,
                "description": "Notificare dezactivare cont client",
                "variables": {"customer_name": "Numele clientului"},
            },
            {
                "key": "customer_deactivated",
                "locale": "en",
                "category": "billing",
                "subject": "Your account has been deactivated - PragmaticHost",
                "body_html": """
                <h2>🚫 Account deactivated</h2>
                <p>Hello {{customer_name}},</p>
                <p>Your PragmaticHost account has been deactivated.</p>
                <p>If you wish to reactivate, contact us at support@pragmatichost.com</p>
                <p>PragmaticHost Team</p>
                """,
                "description": "Customer account deactivation notification",
                "variables": {"customer_name": "Customer name"},
            },
            # REACTIVATION TEMPLATES
            {
                "key": "customer_reactivation",
                "locale": "ro",
                "category": "engagement",
                "subject": "Ne este dor de dumneavoastră! - PragmaticHost",
                "body_html": """
                <h2>Bună ziua {{customer_name}},</h2>
                <p>Am observat că nu v-ați conectat la contul PragmaticHost de ceva timp.</p>
                <p>Dorim să ne asigurăm că totul este în regulă cu contul dumneavoastră
                și că nu aveți nevoie de ajutor.</p>
                <p>Dacă aveți întrebări sau aveți nevoie de asistență, nu ezitați să ne contactați:</p>
                <ul>
                    <li>Email: support@pragmatichost.com</li>
                    <li>Telefon: +40 XXX XXX XXX</li>
                </ul>
                <p>Cu stimă,<br/>Echipa PragmaticHost</p>
                """,
                "description": "Email de reactivare pentru clienți inactivi",
                "variables": {"customer_name": "Numele clientului"},
            },
            {
                "key": "customer_reactivation",
                "locale": "en",
                "category": "engagement",
                "subject": "We miss you! - PragmaticHost",
                "body_html": """
                <h2>Hello {{customer_name}},</h2>
                <p>We noticed you haven't logged into your PragmaticHost account in a while.</p>
                <p>We wanted to check in and make sure everything is OK with your account
                and that you don't need any assistance.</p>
                <p>If you have any questions or need help, please don't hesitate to reach out:</p>
                <ul>
                    <li>Email: support@pragmatichost.com</li>
                    <li>Phone: +40 XXX XXX XXX</li>
                </ul>
                <p>Best regards,<br/>The PragmaticHost Team</p>
                """,
                "description": "Reactivation check-in email for inactive customers",
                "variables": {"customer_name": "Customer name"},
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
