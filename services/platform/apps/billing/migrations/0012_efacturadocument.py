# Generated manually for e-Factura Document model
# Updated to be compatible with feature/app-separation branch migration structure

import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    """
    Add e-Factura Document model for Romanian electronic invoicing.

    This migration depends on 0002_initial to be compatible with both:
    - feature/app-separation branch (squashed migrations 0001 + 0002)
    - feat/services-architecture branch (migrations 0001-0009)

    The dependency is set to 0002_initial which exists in app-separation.
    For services-architecture, migrations run in order so this will work.
    """

    dependencies = [
        ("billing", "0011_usage_based_billing"),
    ]

    operations = [
        migrations.CreateModel(
            name="EFacturaDocument",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "document_type",
                    models.CharField(
                        choices=[
                            ("invoice", "Invoice"),
                            ("credit_note", "Credit Note"),
                            ("debit_note", "Debit Note"),
                        ],
                        default="invoice",
                        help_text="Type of e-Factura document",
                        max_length=20,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("queued", "Queued"),
                            ("submitted", "Submitted"),
                            ("processing", "Processing"),
                            ("accepted", "Accepted"),
                            ("rejected", "Rejected"),
                            ("error", "Error"),
                        ],
                        db_index=True,
                        default="draft",
                        help_text="Current status in the submission lifecycle",
                        max_length=20,
                    ),
                ),
                (
                    "anaf_upload_index",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        help_text="ANAF index_incarcare - returned after upload",
                        max_length=100,
                    ),
                ),
                (
                    "anaf_download_id",
                    models.CharField(
                        blank=True,
                        help_text="ANAF id_descarcare - available after acceptance",
                        max_length=100,
                    ),
                ),
                (
                    "anaf_response_id",
                    models.CharField(
                        blank=True,
                        help_text="ANAF response message ID",
                        max_length=100,
                    ),
                ),
                (
                    "xml_content",
                    models.TextField(
                        blank=True,
                        help_text="Generated UBL 2.1 XML content",
                    ),
                ),
                (
                    "xml_file",
                    models.FileField(
                        blank=True,
                        help_text="Stored XML file path",
                        null=True,
                        upload_to="efactura/xml/%Y/%m/",
                    ),
                ),
                (
                    "xml_hash",
                    models.CharField(
                        blank=True,
                        help_text="SHA-256 hash of XML content for integrity verification",
                        max_length=64,
                    ),
                ),
                (
                    "anaf_response",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Complete ANAF API response data",
                    ),
                ),
                (
                    "validation_errors",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="List of validation errors from ANAF",
                    ),
                ),
                (
                    "signed_pdf",
                    models.FileField(
                        blank=True,
                        help_text="ANAF-signed PDF visualization",
                        null=True,
                        upload_to="efactura/pdf/%Y/%m/",
                    ),
                ),
                (
                    "xml_generated_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When the XML was generated",
                        null=True,
                    ),
                ),
                (
                    "submitted_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When the document was submitted to ANAF",
                        null=True,
                    ),
                ),
                (
                    "response_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When ANAF responded (accepted/rejected)",
                        null=True,
                    ),
                ),
                (
                    "retry_count",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of submission attempts",
                    ),
                ),
                (
                    "next_retry_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When the next retry should be attempted",
                        null=True,
                    ),
                ),
                (
                    "last_error",
                    models.TextField(
                        blank=True,
                        help_text="Last error message for debugging",
                    ),
                ),
                (
                    "environment",
                    models.CharField(
                        choices=[("test", "Test/Sandbox"), ("production", "Production")],
                        default="test",
                        help_text="ANAF environment used for submission",
                        max_length=20,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "invoice",
                    models.OneToOneField(
                        help_text="The invoice this e-Factura document represents",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="efactura_document",
                        to="billing.invoice",
                    ),
                ),
            ],
            options={
                "verbose_name": "e-Factura Document",
                "verbose_name_plural": "e-Factura Documents",
                "db_table": "billing_efactura_document",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="efacturadocument",
            index=models.Index(
                condition=models.Q(("status__in", ["submitted", "processing"])),
                fields=["status", "submitted_at"],
                name="efactura_status_submitted_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="efacturadocument",
            index=models.Index(
                condition=models.Q(("next_retry_at__isnull", False), ("status", "error")),
                fields=["status", "next_retry_at"],
                name="efactura_retry_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="efacturadocument",
            index=models.Index(
                fields=["anaf_upload_index"],
                name="efactura_upload_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="efacturadocument",
            index=models.Index(
                fields=["invoice"],
                name="efactura_invoice_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="efacturadocument",
            constraint=models.UniqueConstraint(
                fields=("invoice",),
                name="unique_efactura_per_invoice",
            ),
        ),
    ]
