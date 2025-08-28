"""
RefundService Usage Examples
Shows how to use the RefundService for various refund scenarios in PRAHO Platform.

This is a demonstration file showing the API usage patterns.
"""

import uuid

from apps.billing.services import RefundData, RefundQueryService, RefundReason, RefundService, RefundType


def example_full_order_refund() -> None:
    """Example: Process a full refund for an order"""
    
    # Prepare refund data
    refund_data: RefundData = {
        'refund_type': RefundType.FULL,
        'amount_cents': 0,  # Ignored for full refunds
        'reason': RefundReason.CUSTOMER_REQUEST,
        'notes': 'Customer was not satisfied with hosting service quality',
        'initiated_by': None,  # Would be actual User instance
        'external_refund_id': 'stripe_re_1234567890',  # From payment processor
        'process_payment_refund': True  # Actually refund the payment
    }
    
    # Process the refund
    order_id = uuid.uuid4()  # Would be actual order ID
    result = RefundService.refund_order(order_id, refund_data)
    
    if result.is_ok():
        refund_result = result.unwrap()
        print("✅ Refund processed successfully!")
        print(f"   Refund ID: {refund_result['refund_id']}")
        print(f"   Amount refunded: {refund_result['amount_refunded_cents']/100:.2f} RON")
        print(f"   Order status updated: {refund_result['order_status_updated']}")
        print(f"   Invoice status updated: {refund_result['invoice_status_updated']}")
        print(f"   Payment refunded: {refund_result['payment_refund_processed']}")
    else:
        print(f"❌ Refund failed: {result.error}")


def example_partial_invoice_refund() -> None:
    """Example: Process a partial refund for an invoice"""
    
    # Prepare partial refund data  
    refund_data: RefundData = {
        'refund_type': RefundType.PARTIAL,
        'amount_cents': 5000,  # 50.00 RON partial refund
        'reason': RefundReason.SERVICE_FAILURE,
        'notes': 'Server downtime compensation - 4 hours outage',
        'initiated_by': None,  # Would be actual User instance
        'external_refund_id': None,  # Credit note instead of payment refund
        'process_payment_refund': False  # Just update records, no payment refund
    }
    
    # Process the refund
    invoice_id = 123  # Would be actual invoice ID (integer)
    result = RefundService.refund_invoice(invoice_id, refund_data)
    
    if result.is_ok():
        refund_result = result.unwrap()
        print("✅ Partial refund processed!")
        print(f"   Amount refunded: {refund_result['amount_refunded_cents']/100:.2f} RON")
        print(f"   Both order and invoice updated: {refund_result['order_status_updated'] and refund_result['invoice_status_updated']}")
    else:
        print(f"❌ Partial refund failed: {result.error}")


def example_check_refund_eligibility() -> None:
    """Example: Check if an entity can be refunded before processing"""
    
    order_id = uuid.uuid4()  # Would be actual order ID
    
    # Check full refund eligibility
    result = RefundService.get_refund_eligibility('order', order_id)
    
    if result.is_ok():
        eligibility = result.unwrap()
        if eligibility['is_eligible']:
            print("✅ Order can be refunded")
            print(f"   Max refund amount: {eligibility['max_refund_amount_cents']/100:.2f} RON")
            print(f"   Already refunded: {eligibility['already_refunded_cents']/100:.2f} RON")
        else:
            print(f"❌ Order cannot be refunded: {eligibility['reason']}")
    else:
        print(f"❌ Eligibility check failed: {result.error}")
    
    # Check partial refund eligibility with specific amount
    partial_amount = 2500  # 25.00 RON
    result = RefundService.get_refund_eligibility('order', order_id, partial_amount)
    
    if result.is_ok():
        eligibility = result.unwrap()
        print(f"Partial refund ({partial_amount/100:.2f} RON) eligible: {eligibility['is_eligible']}")


def example_query_refund_history() -> None:
    """Example: Query refund history for an entity"""
    
    order_id = uuid.uuid4()  # Would be actual order ID
    
    # Get refund history
    result = RefundQueryService.get_entity_refunds('order', order_id)
    
    if result.is_ok():
        refunds = result.unwrap()
        print(f"📊 Found {len(refunds)} refunds for order:")
        
        for refund in refunds:
            amount = refund['amount_cents'] / 100
            print(f"   • {amount:.2f} RON - {refund['reason']} ({refund.get('refunded_at', 'Unknown date')})")
            if refund.get('notes'):
                print(f"     Notes: {refund['notes']}")
    else:
        print(f"❌ Failed to get refund history: {result.error}")


def example_refund_statistics() -> None:
    """Example: Get refund statistics for reporting"""
    
    customer_id = uuid.uuid4()  # Would be actual customer ID
    
    result = RefundQueryService.get_refund_statistics(customer_id=customer_id)
    
    if result.is_ok():
        stats = result.unwrap()
        print("📈 Refund Statistics:")
        print(f"   Total refunds: {stats['total_refunds']}")
        print(f"   Total amount: {stats['total_amount_refunded_cents']/100:.2f} RON")
        print(f"   Orders refunded: {stats['orders_refunded']}")
        print(f"   Invoices refunded: {stats['invoices_refunded']}")
        
        print("\nRefunds by type:")
        for refund_type, count in stats['refunds_by_type'].items():
            print(f"   {refund_type.capitalize()}: {count}")
    else:
        print(f"❌ Failed to get statistics: {result.error}")


def example_error_handling() -> None:
    """Example: Comprehensive error handling patterns"""
    
    # Example 1: Invalid refund amount
    refund_data: RefundData = {
        'refund_type': RefundType.PARTIAL,
        'amount_cents': -1000,  # Invalid negative amount
        'reason': RefundReason.CUSTOMER_REQUEST,
        'notes': 'Invalid refund attempt',
        'initiated_by': None,
        'external_refund_id': None,
        'process_payment_refund': False
    }
    
    order_id = uuid.uuid4()
    result = RefundService.refund_order(order_id, refund_data)
    
    if result.is_err():
        print(f"❌ Expected error for negative amount: {result.error}")
    
    # Example 2: Double refund attempt
    print("\n🔄 Demonstrating double refund prevention...")
    # This would be detected by the service and rejected
    
    # Example 3: Refund larger than available amount
    refund_data['amount_cents'] = 999999999  # Extremely large amount
    result = RefundService.refund_order(order_id, refund_data)
    
    if result.is_err():
        print(f"❌ Expected error for excessive amount: {result.error}")


def main() -> None:
    """Run all examples"""
    print("🔄 PRAHO RefundService Usage Examples")
    print("=" * 50)
    
    print("\n1. Full Order Refund Example:")
    example_full_order_refund()
    
    print("\n2. Partial Invoice Refund Example:")
    example_partial_invoice_refund()
    
    print("\n3. Refund Eligibility Check Example:")
    example_check_refund_eligibility()
    
    print("\n4. Refund History Query Example:")
    example_query_refund_history()
    
    print("\n5. Refund Statistics Example:")
    example_refund_statistics()
    
    print("\n6. Error Handling Examples:")
    example_error_handling()
    
    print("\n✅ All examples completed!")


if __name__ == '__main__':
    main()
