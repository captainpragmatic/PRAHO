# ===============================================================================
# TICKETS API SERIALIZERS - CUSTOMER SUPPORT OPERATIONS <�
# ===============================================================================

from typing import Any, ClassVar

from rest_framework import serializers

from apps.tickets.models import SupportCategory, Ticket, TicketAttachment, TicketComment

# Validation constants
MIN_COMMENT_LENGTH = 2  # Minimum characters for ticket comments

# ===============================================================================
# SUPPORT CATEGORY SERIALIZERS =�
# ===============================================================================


class SupportCategorySerializer(serializers.ModelSerializer):
    """Support category serializer for customer display"""

    class Meta:
        model = SupportCategory
        fields: ClassVar = [
            "id",
            "name",
            "name_en",
            "description",
            "icon",
            "color",
            "auto_assign_to",
        ]


# ===============================================================================
# TICKET LIST SERIALIZER =�
# ===============================================================================


class TicketListSerializer(serializers.ModelSerializer):
    """Ticket list serializer for customer support listing"""

    # Related fields
    customer_name = serializers.CharField(source="customer.name", read_only=True)
    category_name = serializers.CharField(source="category.name", read_only=True)
    category_icon = serializers.CharField(source="category.icon", read_only=True)
    assigned_to_name = serializers.SerializerMethodField()

    # Status/priority display
    priority_display = serializers.CharField(source="get_priority_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    priority_color = serializers.CharField(source="get_priority_color", read_only=True)
    status_color = serializers.CharField(source="get_status_color", read_only=True)

    # New status system fields
    is_awaiting_customer = serializers.BooleanField(read_only=True)
    customer_replied_recently = serializers.BooleanField(read_only=True)
    resolution_code = serializers.CharField(read_only=True)
    closed_at = serializers.DateTimeField(read_only=True)

    # Stats
    comments_count = serializers.SerializerMethodField()
    attachments_count = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields: ClassVar = [
            "id",
            "ticket_number",
            "title",
            "status",
            "status_display",
            "status_color",
            "priority",
            "priority_display",
            "priority_color",
            "source",
            "customer_name",
            "contact_email",
            "contact_person",
            "category_name",
            "category_icon",
            "assigned_to_name",
            "is_escalated",
            "is_public",
            "is_awaiting_customer",
            "customer_replied_recently",
            "resolution_code",
            "closed_at",
            "customer_replied_at",
            "has_customer_replied",
            "comments_count",
            "attachments_count",
            "created_at",
            "updated_at",
        ]

    def get_assigned_to_name(self, obj: "Ticket") -> str:
        """Get assigned staff member name"""
        if obj.assigned_to:
            return obj.assigned_to.get_full_name()
        return ""

    def get_comments_count(self, obj: "Ticket") -> int:
        """Get number of comments/replies"""
        return obj.comments.count()

    def get_attachments_count(self, obj: "Ticket") -> int:
        """Get number of attachments"""
        return obj.attachments.count()


# ===============================================================================
# TICKET COMMENT SERIALIZER =�
# ===============================================================================


class TicketCommentSerializer(serializers.ModelSerializer):
    """Ticket comment/reply serializer"""

    author_name = serializers.SerializerMethodField()
    author_role = serializers.SerializerMethodField()
    is_staff_reply = serializers.SerializerMethodField()
    attachments = serializers.SerializerMethodField()

    class Meta:
        model = TicketComment
        fields: ClassVar = [
            "id",
            "content",
            "comment_type",
            "author_name",
            "author_email",
            "author_role",
            "is_staff_reply",
            "is_public",
            "is_solution",
            "time_spent",
            "created_at",
            "updated_at",
            "attachments",
        ]

    def get_author_name(self, obj: "TicketComment") -> str:
        """Get comment author name"""
        return obj.get_author_name()

    def get_author_role(self, obj: "TicketComment") -> str:
        """Get author role for display.

        Any Django staff user or a user with a non-empty staff_role is treated as Staff.
        """
        author = getattr(obj, "author", None)
        if author and (getattr(author, "is_staff", False) or getattr(author, "staff_role", "") != ""):
            return "Staff"
        return "Customer"

    def get_is_staff_reply(self, obj: "TicketComment") -> bool:
        """Check if comment is from staff.

        Internal/support comment types are staff replies; otherwise infer from author flags.
        """
        if obj.comment_type in ["support", "internal"]:
            return True
        author = getattr(obj, "author", None)
        return bool(author and (getattr(author, "is_staff", False) or getattr(author, "staff_role", "") != ""))

    def get_attachments(self, obj: "TicketComment") -> list[dict[str, Any]]:
        """Get attachments for this comment"""
        qs = obj.attachments.all()
        return TicketAttachmentSerializer(qs, many=True).data


# ===============================================================================
# TICKET ATTACHMENT SERIALIZER =�
# ===============================================================================


class TicketAttachmentSerializer(serializers.ModelSerializer):
    """Ticket attachment serializer"""

    file_size_display = serializers.CharField(source="get_file_size_display", read_only=True)
    file_url = serializers.SerializerMethodField()
    is_image = serializers.SerializerMethodField()

    class Meta:
        model = TicketAttachment
        fields: ClassVar = [
            "id",
            "filename",
            "file_size",
            "file_size_display",
            "content_type",
            "file_url",
            "is_image",
            "is_safe",
            "uploaded_at",
        ]

    def get_file_url(self, obj: "TicketAttachment") -> str:
        """Get secure file download URL"""
        if obj.file:
            # Return relative URL for security (actual download handled by view)
            return f"/api/tickets/{obj.ticket_id}/attachments/{obj.id}/download/"
        return ""

    def get_is_image(self, obj: "TicketAttachment") -> bool:
        """Check if attachment is an image"""
        return obj.content_type.startswith("image/") if obj.content_type else False


# ===============================================================================
# TICKET DETAIL SERIALIZER =�
# ===============================================================================


class TicketDetailSerializer(serializers.ModelSerializer):
    """Complete ticket details with comments and attachments"""

    # Related objects
    customer_name = serializers.CharField(source="customer.name", read_only=True)
    customer_email = serializers.CharField(source="customer.email", read_only=True)
    category = SupportCategorySerializer(read_only=True)
    assigned_to_name = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()

    # Status/priority display
    priority_display = serializers.CharField(source="get_priority_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    priority_color = serializers.CharField(source="get_priority_color", read_only=True)
    status_color = serializers.CharField(source="get_status_color", read_only=True)

    # New status system fields
    is_awaiting_customer = serializers.BooleanField(read_only=True)
    customer_replied_recently = serializers.BooleanField(read_only=True)
    resolution_code = serializers.CharField(read_only=True)
    closed_at = serializers.DateTimeField(read_only=True)

    # Related data
    # Filtered for customer context to avoid exposing internal notes/attachments
    comments = serializers.SerializerMethodField()
    attachments = serializers.SerializerMethodField()

    # Service info
    related_service_name = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields: ClassVar = [
            "id",
            "ticket_number",
            "title",
            "description",
            "status",
            "status_display",
            "status_color",
            "priority",
            "priority_display",
            "priority_color",
            "source",
            "customer_name",
            "customer_email",
            "contact_person",
            "contact_email",
            "contact_phone",
            "category",
            "assigned_to_name",
            "created_by_name",
            "related_service_name",
            "is_escalated",
            "is_public",
            "is_awaiting_customer",
            "customer_replied_recently",
            "resolution_code",
            "closed_at",
            "customer_replied_at",
            "has_customer_replied",
            "estimated_hours",
            "actual_hours",
            "satisfaction_rating",
            "satisfaction_comment",
            "comments",
            "attachments",
            "created_at",
            "updated_at",
        ]

    def get_assigned_to_name(self, obj: "Ticket") -> str:
        """Get assigned staff member name"""
        if obj.assigned_to:
            return obj.assigned_to.get_full_name()
        return ""

    def get_created_by_name(self, obj: "Ticket") -> str:
        """Get ticket creator name"""
        if obj.created_by:
            return obj.created_by.get_full_name()
        return ""

    def get_related_service_name(self, obj: "Ticket") -> str:
        """Get related service name if any"""
        if obj.related_service:
            return str(obj.related_service)
        return ""

    def get_comments(self, obj: "Ticket") -> list[dict[str, Any]]:
        """Return comments, filtering out non-public ones for customer context."""
        qs = obj.comments.all()
        if self.context.get("for_customer"):
            qs = qs.filter(is_public=True)
        return TicketCommentSerializer(qs, many=True).data

    def get_attachments(self, obj: "Ticket") -> list[dict[str, Any]]:
        """Return attachments linked to public comments only for customer context."""
        qs = obj.attachments.all()
        if self.context.get("for_customer"):
            qs = qs.filter(comment__is_public=True)
        return TicketAttachmentSerializer(qs, many=True).data


# ===============================================================================
# TICKET CREATION SERIALIZER 	
# ===============================================================================


class TicketCreateSerializer(serializers.ModelSerializer):
    """Ticket creation serializer for customer submissions"""

    class Meta:
        model = Ticket
        fields: ClassVar = [
            "title",
            "description",
            "priority",
            "category",
            "contact_person",
            "contact_email",
            "contact_phone",
            "related_service",
        ]
        extra_kwargs: ClassVar = {
            "title": {"required": True},
            "description": {"required": True},
            "priority": {"default": "normal"},
        }


# ===============================================================================
# COMMENT CREATION SERIALIZER =�
# ===============================================================================


class CommentCreateSerializer(serializers.ModelSerializer):
    """Comment creation serializer for customer replies"""

    class Meta:
        model = TicketComment
        fields: ClassVar = [
            "content",
        ]
        extra_kwargs: ClassVar = {"content": {"required": True}}

    def validate_content(self, value: str) -> str:
        """Validate comment content"""
        if not value or len(value.strip()) < MIN_COMMENT_LENGTH:
            raise serializers.ValidationError("Comment must be at least 2 characters long")
        return value.strip()


# ===============================================================================
# TICKETS SUMMARY SERIALIZER =�
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
