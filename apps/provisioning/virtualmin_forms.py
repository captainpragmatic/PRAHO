"""
Virtualmin Management Forms - PRAHO Platform
Django forms for Virtualmin server and account management with Romanian compliance.
"""

import re
from typing import Any, ClassVar

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.ui.widgets import (
    PRAHOCheckboxWidget,
    PRAHOPasswordWidget,
    PRAHOSelectWidget,
    PRAHOTextWidget,
)

from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_validators import VirtualminValidator


class VirtualminServerForm(forms.ModelForm):
    """
    Form for creating and editing Virtualmin servers.
    Uses PRAHO UI widgets for consistent styling.
    """
    
    # Override password field to hide in form (use credential vault)
    api_password = forms.CharField(
        widget=PRAHOPasswordWidget(attrs={
            'placeholder': 'Enter API password...'
        }),
        required=False,
        help_text=_("API password for Virtualmin authentication")
    )
    
    class Meta:
        model = VirtualminServer
        fields: ClassVar[list[str]] = [
            'name', 'hostname', 'api_port', 'api_username', 
            'use_ssl', 'ssl_verify', 'status', 'max_domains', 'max_disk_gb',
            'max_bandwidth_gb'
        ]
        widgets: ClassVar[dict[str, Any]] = {
            'name': PRAHOTextWidget(attrs={
                'placeholder': 'Server display name (e.g., "Primary Web Server")'
            }),
            'hostname': PRAHOTextWidget(attrs={
                'placeholder': 'server.example.com'
            }),
            'api_port': PRAHOTextWidget(attrs={
                'placeholder': '10000',
                'type': 'number'
            }),
            'api_username': PRAHOTextWidget(attrs={
                'placeholder': 'webmin_api_user'
            }),
            'use_ssl': PRAHOCheckboxWidget(),
            'ssl_verify': PRAHOCheckboxWidget(),
            'status': PRAHOSelectWidget(),
            'max_domains': PRAHOTextWidget(attrs={
                'placeholder': '100',
                'type': 'number'
            }),
            'max_disk_gb': PRAHOTextWidget(attrs={
                'placeholder': '1000',
                'type': 'number'
            }),
            'max_bandwidth_gb': PRAHOTextWidget(attrs={
                'placeholder': '5000',
                'type': 'number'
            })
        }
        
    def clean_hostname(self) -> str:
        """Validate hostname format."""
        hostname = self.cleaned_data.get('hostname', '')
        
        # Use Virtualmin validator for server hostname validation
        validator = VirtualminValidator()
        try:
            validator.validate_server_hostname(hostname)
        except ValidationError as e:
            raise ValidationError(f"Invalid hostname format: {e.message}") from e
            
        return hostname
        
    def clean_api_username(self) -> str:
        """Validate API username format (allows 'root' for Virtualmin API access)."""
        username = self.cleaned_data.get('api_username', '')
        
        validator = VirtualminValidator()
        try:
            validator.validate_api_username(username)
        except ValidationError as e:
            raise ValidationError(f"Invalid username format: {e.message}") from e
            
        return username
        
    def clean_api_password(self) -> str:
        """Validate API password strength."""
        password = self.cleaned_data.get('api_password', '')
        
        if not password and not self.instance.pk:
            # New server requires password
            raise ValidationError("API password is required for new servers")
            
        if password:
            validator = VirtualminValidator()
            try:
                validator.validate_password(password)
            except ValidationError as e:
                raise ValidationError(f"Password validation failed: {e.message}") from e
                
        return password
        
    def save(self, commit: bool = True) -> VirtualminServer:
        """Save server and handle password encryption."""
        server = super().save(commit=False)
        
        # Handle password encryption if provided
        api_password = self.cleaned_data.get('api_password')
        if api_password:
            server.set_api_password(api_password)
            
        if commit:
            server.save()
            
        return server


class VirtualminBackupForm(forms.Form):
    """
    Form for creating Virtualmin domain backups.
    Provides options for backup type and included features.
    """
    
    BACKUP_TYPE_CHOICES: ClassVar[list[tuple[str, str]]] = [
        ('full', _('Full Backup - Complete domain backup with all data')),
        ('incremental', _('Incremental Backup - Changes since last full backup')),
        ('config_only', _('Configuration Only - Settings and structure only'))
    ]
    
    backup_type = forms.ChoiceField(
        choices=BACKUP_TYPE_CHOICES,
        initial='full',
        widget=PRAHOSelectWidget(),
        help_text=_("Type of backup to create")
    )
    
    include_email = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Include Email Data"),
        help_text=_("Backup email accounts, messages, and mail settings")
    )
    
    include_databases = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Include Databases"),
        help_text=_("Backup MySQL and PostgreSQL databases")
    )
    
    include_files = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Include Web Files"),
        help_text=_("Backup website files and uploads")
    )
    
    include_ssl = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Include SSL Certificates"),
        help_text=_("Backup SSL certificates and private keys")
    )
    
    def clean(self) -> dict[str, Any]:
        """Validate that at least one feature is included."""
        cleaned_data = super().clean()
        
        include_email = cleaned_data.get('include_email', False)
        include_databases = cleaned_data.get('include_databases', False)
        include_files = cleaned_data.get('include_files', False)
        include_ssl = cleaned_data.get('include_ssl', False)
        
        if not any([include_email, include_databases, include_files, include_ssl]):
            raise ValidationError(
                "At least one feature must be included in the backup"
            )
            
        return cleaned_data


class VirtualminRestoreForm(forms.Form):
    """
    Form for restoring Virtualmin domains from backups.
    Allows selection of backup and restore options.
    """
    
    backup_id = forms.ChoiceField(
        widget=PRAHOSelectWidget(),
        help_text=_("Select backup to restore from")
    )
    
    restore_email = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Restore Email Data"),
        help_text=_("Restore email accounts, messages, and mail settings")
    )
    
    restore_databases = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Restore Databases"),
        help_text=_("Restore MySQL and PostgreSQL databases")
    )
    
    restore_files = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Restore Web Files"),
        help_text=_("Restore website files and uploads")
    )
    
    restore_ssl = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Restore SSL Certificates"),
        help_text=_("Restore SSL certificates and private keys")
    )
    
    confirm_restore = forms.BooleanField(
        required=True,
        widget=PRAHOCheckboxWidget(),
        label=_("Confirm Restore Operation"),
        help_text=_("I understand this will overwrite existing data")
    )
    
    def __init__(self, *args: Any, available_backups: list[dict[str, Any]] | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        
        if available_backups:
            backup_choices = []
            for backup in available_backups:
                backup_label = f"{backup['backup_id']} - {backup['backup_type'].title()} ({backup['created_at']})"
                backup_choices.append((backup['backup_id'], backup_label))
            
            self.fields['backup_id'].choices = backup_choices
        else:
            self.fields['backup_id'].choices = []
            
    def clean_backup_id(self) -> str:
        """Validate backup ID exists and is accessible."""
        backup_id = self.cleaned_data.get('backup_id')
        
        if not backup_id:
            raise ValidationError("Please select a backup to restore from")
            
        # Additional validation could check backup accessibility
        return backup_id
        
    def clean(self) -> dict[str, Any]:
        """Validate that at least one feature is being restored."""
        cleaned_data = super().clean()
        
        restore_email = cleaned_data.get('restore_email', False)
        restore_databases = cleaned_data.get('restore_databases', False)
        restore_files = cleaned_data.get('restore_files', False)
        restore_ssl = cleaned_data.get('restore_ssl', False)
        
        if not any([restore_email, restore_databases, restore_files, restore_ssl]):
            raise ValidationError(
                "At least one feature must be selected for restore"
            )
            
        return cleaned_data


class VirtualminHealthCheckForm(forms.Form):
    """
    Form for manually triggering server health checks.
    Simple form with confirmation and options.
    """
    
    check_connectivity = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Check API Connectivity"),
        help_text=_("Test basic API connection and authentication")
    )
    
    check_disk_space = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Check Disk Space"),
        help_text=_("Verify available disk space on server")
    )
    
    check_domain_count = forms.BooleanField(
        initial=True,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Update Domain Count"),
        help_text=_("Refresh count of hosted domains")
    )
    
    force_check = forms.BooleanField(
        initial=False,
        required=False,
        widget=PRAHOCheckboxWidget(),
        label=_("Force Check"),
        help_text=_("Ignore cache and perform fresh health check")
    )


class VirtualminBulkActionForm(forms.Form):
    """
    Form for bulk actions on Virtualmin accounts.
    Allows mass operations with safety confirmations.
    """
    
    ACTION_CHOICES: ClassVar[list[tuple[str, str]]] = [
        ('backup', _('Create Backups')),
        ('suspend', _('Suspend Accounts')),
        ('activate', _('Activate Accounts')),
        ('health_check', _('Health Check'))
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        widget=PRAHOSelectWidget(),
        help_text=_("Select action to perform on selected accounts")
    )
    
    selected_accounts = forms.CharField(
        widget=forms.HiddenInput(),
        help_text=_("Comma-separated list of account IDs")
    )
    
    confirm_bulk_action = forms.BooleanField(
        required=True,
        widget=PRAHOCheckboxWidget(),
        label=_("Confirm Bulk Action"),
        help_text=_("I understand this action will affect multiple accounts")
    )
    
    # Backup-specific options (shown conditionally)
    backup_type = forms.ChoiceField(
        choices=VirtualminBackupForm.BACKUP_TYPE_CHOICES,
        initial='full',
        required=False,
        widget=PRAHOSelectWidget(),
        help_text=_("Backup type for bulk backup operation")
    )
    
    def clean_selected_accounts(self) -> list[str]:
        """Parse and validate selected account IDs."""
        accounts_str = self.cleaned_data.get('selected_accounts', '')
        
        if not accounts_str.strip():
            raise ValidationError("No accounts selected for bulk action")
            
        try:
            account_ids = [aid.strip() for aid in accounts_str.split(',') if aid.strip()]
            
            if not account_ids:
                raise ValidationError("No valid account IDs provided")
                
            return account_ids
            
        except Exception as e:
            raise ValidationError("Invalid account ID format") from e
            
    def clean(self) -> dict[str, Any]:
        """Validate form based on selected action."""
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        
        if action == 'backup' and not cleaned_data.get('backup_type'):
                raise ValidationError("Backup type is required for backup action")
                
        return cleaned_data


class VirtualminAccountForm(forms.ModelForm):
    """
    Form for creating new Virtualmin accounts.
    Includes domain validation and server selection.
    """
    
    class Meta:
        model = VirtualminAccount
        fields: ClassVar = [
            'domain', 'server', 'service', 'virtualmin_username',
            'disk_quota_mb', 'bandwidth_quota_mb', 'status'
        ]
        widgets: ClassVar = {
            'domain': PRAHOTextWidget(attrs={'placeholder': 'example.com'}),
            'virtualmin_username': PRAHOTextWidget(attrs={'placeholder': 'username'}),
            'disk_quota_mb': PRAHOTextWidget(attrs={'placeholder': '1000', 'type': 'number'}),
            'bandwidth_quota_mb': PRAHOTextWidget(attrs={'placeholder': '10000', 'type': 'number'}),
            'server': PRAHOSelectWidget(),
            'service': PRAHOSelectWidget(),
            'status': PRAHOSelectWidget(),
        }
        
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        
        # Filter servers to only active ones
        self.fields['server'].queryset = VirtualminServer.objects.filter(status='active')
        
        # Make some fields required
        self.fields['domain'].required = True
        self.fields['server'].required = True
        self.fields['virtualmin_username'].required = True
        
        # Set default quota values
        self.fields['disk_quota_mb'].initial = 1000
        self.fields['bandwidth_quota_mb'].initial = 10000
        self.fields['status'].initial = 'active'
        
    def clean_domain(self) -> str:
        """Validate domain format and uniqueness."""
        domain = self.cleaned_data.get('domain', '').strip().lower()
        
        if not domain:
            raise ValidationError(_("Domain is required"))
            
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$', domain):
            raise ValidationError(_("Invalid domain format"))
            
        # Check uniqueness
        if VirtualminAccount.objects.filter(domain=domain).exists():
            raise ValidationError(_("An account with this domain already exists"))
            
        return domain
