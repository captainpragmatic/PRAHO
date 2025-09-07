# ===============================================================================
# TICKETS API SERIALIZERS - CUSTOMER SUPPORT OPERATIONS <«
# ===============================================================================

from rest_framework import serializers
from apps.tickets.models import Ticket, TicketComment, SupportCategory, TicketAttachment
from apps.customers.models import Customer


# ===============================================================================
# SUPPORT CATEGORY SERIALIZERS =Â
# ===============================================================================

class SupportCategorySerializer(serializers.ModelSerializer):
    """Support category serializer for customer display"""
    
    class Meta:
        model = SupportCategory
        fields = [
            'id',
            'name',
            'name_en', 
            'description',
            'icon',
            'color',
            'sla_response_hours',
            'sla_resolution_hours'
        ]


# ===============================================================================
# TICKET LIST SERIALIZER =Ë
# ===============================================================================

class TicketListSerializer(serializers.ModelSerializer):
    """Ticket list serializer for customer support listing"""
    
    # Related fields
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    category_icon = serializers.CharField(source='category.icon', read_only=True)
    assigned_to_name = serializers.SerializerMethodField()
    
    # Status/priority display
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    priority_color = serializers.CharField(source='get_priority_color', read_only=True)
    status_color = serializers.CharField(source='get_status_color', read_only=True)
    
    # SLA tracking
    is_sla_breach_response = serializers.BooleanField(read_only=True)
    is_sla_breach_resolution = serializers.BooleanField(read_only=True)
    
    # Stats
    comments_count = serializers.SerializerMethodField()
    attachments_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Ticket
        fields = [
            'id',
            'ticket_number',
            'title',
            'status',
            'status_display',
            'status_color',
            'priority',
            'priority_display', 
            'priority_color',
            'source',
            'customer_name',
            'contact_email',
            'contact_person',
            'category_name',
            'category_icon',
            'assigned_to_name',
            'is_escalated',
            'is_public',
            'requires_customer_response',
            'is_sla_breach_response',
            'is_sla_breach_resolution',
            'sla_response_due',
            'sla_resolution_due',
            'first_response_at',
            'resolved_at',
            'comments_count',
            'attachments_count',
            'created_at',
            'updated_at'
        ]
    
    def get_assigned_to_name(self, obj) -> str:
        """Get assigned staff member name"""
        if obj.assigned_to:
            return obj.assigned_to.get_full_name()
        return ""
    
    def get_comments_count(self, obj) -> int:
        """Get number of comments/replies"""
        return obj.comments.count()
    
    def get_attachments_count(self, obj) -> int:
        """Get number of attachments"""
        return obj.attachments.count()


# ===============================================================================
# TICKET COMMENT SERIALIZER =¬
# ===============================================================================

class TicketCommentSerializer(serializers.ModelSerializer):
    """Ticket comment/reply serializer"""
    
    author_name = serializers.SerializerMethodField()
    author_role = serializers.SerializerMethodField()
    is_staff_reply = serializers.SerializerMethodField()
    
    class Meta:
        model = TicketComment
        fields = [
            'id',
            'content',
            'comment_type',
            'author_name',
            'author_email',
            'author_role',
            'is_staff_reply',
            'is_public',
            'is_solution',
            'time_spent',
            'created_at',
            'updated_at'
        ]
    
    def get_author_name(self, obj) -> str:
        """Get comment author name"""
        return obj.get_author_name()
    
    def get_author_role(self, obj) -> str:
        """Get author role for display"""
        if obj.author and obj.author.role in ['support', 'admin', 'manager']:
            return 'Staff'
        return 'Customer'
    
    def get_is_staff_reply(self, obj) -> bool:
        """Check if comment is from staff"""
        return obj.comment_type in ['support', 'internal'] or (
            obj.author and obj.author.role in ['support', 'admin', 'manager']
        )


# ===============================================================================
# TICKET ATTACHMENT SERIALIZER =Î
# ===============================================================================

class TicketAttachmentSerializer(serializers.ModelSerializer):
    """Ticket attachment serializer"""
    
    file_size_display = serializers.CharField(source='get_file_size_display', read_only=True)
    file_url = serializers.SerializerMethodField()
    is_image = serializers.SerializerMethodField()
    
    class Meta:
        model = TicketAttachment
        fields = [
            'id',
            'filename',
            'file_size',
            'file_size_display',
            'content_type',
            'file_url',
            'is_image',
            'is_safe',
            'uploaded_at'
        ]
    
    def get_file_url(self, obj) -> str:
        """Get secure file download URL"""
        if obj.file:
            # Return relative URL for security (actual download handled by view)
            return f"/api/tickets/{obj.ticket_id}/attachments/{obj.id}/download/"
        return ""
    
    def get_is_image(self, obj) -> bool:
        """Check if attachment is an image"""
        return obj.content_type.startswith('image/') if obj.content_type else False


# ===============================================================================
# TICKET DETAIL SERIALIZER =Ä
# ===============================================================================

class TicketDetailSerializer(serializers.ModelSerializer):
    """Complete ticket details with comments and attachments"""
    
    # Related objects
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    customer_email = serializers.CharField(source='customer.email', read_only=True)
    category = SupportCategorySerializer(read_only=True)
    assigned_to_name = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()
    
    # Status/priority display  
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    priority_color = serializers.CharField(source='get_priority_color', read_only=True)
    status_color = serializers.CharField(source='get_status_color', read_only=True)
    
    # SLA tracking
    is_sla_breach_response = serializers.BooleanField(read_only=True)
    is_sla_breach_resolution = serializers.BooleanField(read_only=True)
    
    # Related data
    comments = TicketCommentSerializer(many=True, read_only=True)
    attachments = TicketAttachmentSerializer(many=True, read_only=True)
    
    # Service info
    related_service_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Ticket
        fields = [
            'id',
            'ticket_number',
            'title',
            'description',
            'status',
            'status_display',
            'status_color',
            'priority',
            'priority_display',
            'priority_color',
            'source',
            'customer_name',
            'customer_email',
            'contact_person',
            'contact_email',
            'contact_phone',
            'category',
            'assigned_to_name',
            'created_by_name',
            'related_service_name',
            'is_escalated',
            'is_public',
            'requires_customer_response',
            'is_sla_breach_response',
            'is_sla_breach_resolution',
            'sla_response_due',
            'sla_resolution_due',
            'first_response_at',
            'resolved_at',
            'estimated_hours',
            'actual_hours',
            'satisfaction_rating',
            'satisfaction_comment',
            'comments',
            'attachments',
            'created_at',
            'updated_at'
        ]
    
    def get_assigned_to_name(self, obj) -> str:
        """Get assigned staff member name"""
        if obj.assigned_to:
            return obj.assigned_to.get_full_name()
        return ""
    
    def get_created_by_name(self, obj) -> str:
        """Get ticket creator name"""
        if obj.created_by:
            return obj.created_by.get_full_name()
        return ""
    
    def get_related_service_name(self, obj) -> str:
        """Get related service name if any"""
        if obj.related_service:
            return str(obj.related_service)
        return ""


# ===============================================================================
# TICKET CREATION SERIALIZER 	
# ===============================================================================

class TicketCreateSerializer(serializers.ModelSerializer):
    """Ticket creation serializer for customer submissions"""
    
    class Meta:
        model = Ticket
        fields = [
            'title',
            'description',
            'priority',
            'category',
            'contact_person',
            'contact_email', 
            'contact_phone',
            'related_service'
        ]
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': True},
            'contact_email': {'required': True},
            'priority': {'default': 'normal'}
        }
    
    def validate_contact_email(self, value):
        """Validate contact email format"""
        if not value or '@' not in value:
            raise serializers.ValidationError("Valid email address is required")
        return value


# ===============================================================================
# COMMENT CREATION SERIALIZER =­
# ===============================================================================

class CommentCreateSerializer(serializers.ModelSerializer):
    """Comment creation serializer for customer replies"""
    
    class Meta:
        model = TicketComment
        fields = [
            'content',
        ]
        extra_kwargs = {
            'content': {'required': True}
        }
    
    def validate_content(self, value):
        """Validate comment content"""
        if not value or len(value.strip()) < 10:
            raise serializers.ValidationError("Comment must be at least 10 characters long")
        return value.strip()


# ===============================================================================
# TICKETS SUMMARY SERIALIZER =Ê
# ===============================================================================

class TicketsSummarySerializer(serializers.Serializer):
    """Customer tickets summary for dashboard widgets"""
    
    total_tickets = serializers.IntegerField()
    open_tickets = serializers.IntegerField()
    pending_tickets = serializers.IntegerField()
    resolved_tickets = serializers.IntegerField()
    average_response_time_hours = serializers.FloatField()
    satisfaction_rating = serializers.FloatField()
    recent_tickets = TicketListSerializer(many=True)