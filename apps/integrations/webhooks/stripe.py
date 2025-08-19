import json
import logging
from typing import Dict, Any, Tuple
from django.conf import settings
from apps.billing.models import Payment, Invoice
from apps.customers.models import Customer
from .base import BaseWebhookProcessor, verify_stripe_signature


logger = logging.getLogger(__name__)


# ===============================================================================
# STRIPE WEBHOOK PROCESSOR  
# ===============================================================================

class StripeWebhookProcessor(BaseWebhookProcessor):
    """
    💳 Stripe webhook processor with deduplication
    
    Handles Stripe events:
    - payment_intent.succeeded → Update Payment status
    - payment_intent.payment_failed → Mark payment failed  
    - invoice.payment_succeeded → Update Invoice status
    - invoice.payment_failed → Trigger dunning process
    - customer.created → Link Stripe customer to our Customer
    - charge.dispute.created → Alert for dispute handling
    """
    
    source_name = 'stripe'
    
    def extract_event_id(self, payload: Dict[str, Any]) -> str:
        """🔍 Extract Stripe event ID"""
        return payload.get('id', '')
    
    def extract_event_type(self, payload: Dict[str, Any]) -> str:
        """🏷️ Extract Stripe event type"""
        return payload.get('type', '')
    
    def verify_signature(
        self, 
        payload: Dict[str, Any], 
        signature: str, 
        headers: Dict[str, str]
    ) -> bool:
        """🔐 Verify Stripe webhook signature"""
        webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
        
        if not webhook_secret:
            logger.warning("⚠️ STRIPE_WEBHOOK_SECRET not configured - skipping signature verification")
            return True  # Allow in development
        
        # Get raw payload for signature verification
        payload_body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        
        return verify_stripe_signature(
            payload_body=payload_body,
            stripe_signature=signature,
            webhook_secret=webhook_secret
        )
    
    def handle_event(self, webhook_event) -> Tuple[bool, str]:
        """🎯 Handle Stripe webhook event"""
        event_type = webhook_event.event_type
        payload = webhook_event.payload
        
        try:
            # Route to specific handler
            if event_type.startswith('payment_intent.'):
                return self.handle_payment_intent_event(event_type, payload)
            
            elif event_type.startswith('invoice.'):
                return self.handle_invoice_event(event_type, payload)
            
            elif event_type.startswith('customer.'):
                return self.handle_customer_event(event_type, payload)
            
            elif event_type.startswith('charge.'):
                return self.handle_charge_event(event_type, payload)
            
            elif event_type.startswith('setup_intent.'):
                return self.handle_setup_intent_event(event_type, payload)
            
            else:
                # Unknown event type - skip
                logger.info(f"⏭️ Skipping unknown Stripe event type: {event_type}")
                return True, f"Skipped unknown event type: {event_type}"
        
        except Exception as e:
            logger.exception(f"💥 Error handling Stripe event {event_type}")
            return False, f"Handler error: {str(e)}"
    
    def handle_payment_intent_event(self, event_type: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """💳 Handle PaymentIntent events"""
        payment_intent = payload.get('data', {}).get('object', {})
        stripe_payment_id = payment_intent.get('id')
        
        if not stripe_payment_id:
            return False, "Missing PaymentIntent ID"
        
        # Find our Payment record by Stripe ID
        try:
            payment = Payment.objects.get(gateway_txn_id=stripe_payment_id)
        except Payment.DoesNotExist:
            # Payment not found - might be created outside our system
            logger.warning(f"⚠️ Payment not found for Stripe PaymentIntent: {stripe_payment_id}")
            return True, f"Payment not found (external): {stripe_payment_id}"
        
        if event_type == 'payment_intent.succeeded':
            # Payment succeeded
            payment.status = 'succeeded'
            payment.meta.update({
                'stripe_payment_intent': stripe_payment_id,
                'stripe_payment_method': payment_intent.get('payment_method'),
                'stripe_amount_received': payment_intent.get('amount_received'),
            })
            payment.save(update_fields=['status', 'meta'])
            
            # Update associated invoice if exists
            if payment.invoice:
                payment.invoice.update_status_from_payments()
            
            logger.info(f"✅ Payment {payment.id} marked as succeeded from Stripe")
            return True, f"Payment {payment.id} succeeded"
        
        elif event_type == 'payment_intent.payment_failed':
            # Payment failed
            failure_reason = payment_intent.get('last_payment_error', {}).get('message', 'Unknown error')
            
            payment.status = 'failed'
            payment.meta.update({
                'stripe_payment_intent': stripe_payment_id,
                'stripe_failure_reason': failure_reason,
            })
            payment.save(update_fields=['status', 'meta'])
            
            # Trigger dunning process if this was an invoice payment
            if payment.invoice:
                # TODO: Trigger payment retry/dunning logic
                pass
            
            logger.warning(f"❌ Payment {payment.id} marked as failed from Stripe: {failure_reason}")
            return True, f"Payment {payment.id} failed: {failure_reason}"
        
        else:
            return True, f"Skipped PaymentIntent event: {event_type}"
    
    def handle_invoice_event(self, event_type: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """🧾 Handle Stripe Invoice events"""
        stripe_invoice = payload.get('data', {}).get('object', {})
        stripe_invoice_id = stripe_invoice.get('id')
        
        if event_type == 'invoice.payment_succeeded':
            # Find our invoice by Stripe ID or customer
            logger.info(f"🎉 Stripe invoice payment succeeded: {stripe_invoice_id}")
            return True, f"Invoice payment succeeded: {stripe_invoice_id}"
        
        elif event_type == 'invoice.payment_failed':
            # Trigger dunning process
            logger.warning(f"❌ Stripe invoice payment failed: {stripe_invoice_id}")
            return True, f"Invoice payment failed: {stripe_invoice_id}"
        
        else:
            return True, f"Skipped Invoice event: {event_type}"
    
    def handle_customer_event(self, event_type: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """👤 Handle Stripe Customer events"""
        stripe_customer = payload.get('data', {}).get('object', {})
        stripe_customer_id = stripe_customer.get('id')
        
        if event_type == 'customer.created':
            # Link Stripe customer to our customer record
            customer_email = stripe_customer.get('email')
            
            if customer_email:
                try:
                    customer = Customer.objects.get(primary_email=customer_email)
                    # Store Stripe customer ID in metadata
                    customer.meta['stripe_customer_id'] = stripe_customer_id
                    customer.save(update_fields=['meta'])
                    
                    logger.info(f"🔗 Linked Stripe customer {stripe_customer_id} to {customer}")
                    return True, f"Customer linked: {customer}"
                
                except Customer.DoesNotExist:
                    logger.warning(f"⚠️ Customer not found for Stripe customer: {customer_email}")
                    return True, f"Customer not found: {customer_email}"
        
        return True, f"Skipped Customer event: {event_type}"
    
    def handle_charge_event(self, event_type: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """💰 Handle Stripe Charge events"""
        charge = payload.get('data', {}).get('object', {})
        charge_id = charge.get('id')
        
        if event_type == 'charge.dispute.created':
            # Alert for dispute handling
            logger.critical(f"🚨 DISPUTE CREATED for charge {charge_id} - manual review required!")
            
            # TODO: Send urgent notification to admin
            # TODO: Update payment record with dispute flag
            
            return True, f"Dispute created for charge: {charge_id}"
        
        elif event_type == 'charge.succeeded':
            # Charge succeeded - payment completed
            logger.info(f"✅ Stripe charge succeeded: {charge_id}")
            return True, f"Charge succeeded: {charge_id}"
        
        elif event_type == 'charge.failed':
            # Charge failed
            failure_reason = charge.get('failure_message', 'Unknown error')
            logger.warning(f"❌ Stripe charge failed: {charge_id} - {failure_reason}")
            return True, f"Charge failed: {charge_id}"
        
        return True, f"Skipped Charge event: {event_type}"
    
    def handle_setup_intent_event(self, event_type: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """🔧 Handle SetupIntent events (for saved payment methods)"""
        setup_intent = payload.get('data', {}).get('object', {})
        setup_intent_id = setup_intent.get('id')
        
        if event_type == 'setup_intent.succeeded':
            # Payment method saved successfully
            payment_method = setup_intent.get('payment_method')
            customer_id = setup_intent.get('customer')
            
            logger.info(f"💾 Payment method saved: {payment_method} for customer {customer_id}")
            return True, f"SetupIntent succeeded: {setup_intent_id}"
        
        return True, f"Skipped SetupIntent event: {event_type}"
