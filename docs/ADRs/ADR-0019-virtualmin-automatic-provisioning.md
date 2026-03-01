# ADR-0019: VirtualMin Automatic Provisioning System

## Status
**Status:** Accepted
**Date:** 2025-09-04
**Decision Makers:** PRAHO Development Team
**Stakeholders:** Operations Team, Customer Support, Romanian Hosting Partners

## Context

PRAHO Platform required a production-ready automatic provisioning system for VirtualMin hosting accounts to eliminate manual provisioning overhead and ensure reliable service activation for Romanian hosting providers. The existing manual process was error-prone, time-intensive, and didn't scale with business growth.

### Current State Analysis
- **Manual Process**: Staff manually created VirtualMin accounts after service activation
- **Error-Prone**: Domain conflicts, configuration mistakes, and inconsistent setups
- **No Protection**: Accidental account deletions could destroy customer data
- **Limited Traceability**: Insufficient audit trails for compliance requirements
- **Scalability Issues**: Manual process became bottleneck for customer onboarding

## Problem Statement

### Primary Challenges
1. **Manual Provisioning Overhead**: Staff spent 15-30 minutes per hosting service activation
2. **Data Integrity Gaps**: No database-level domain uniqueness enforcement
3. **Accidental Deletions**: Production accounts could be deleted without protection mechanisms
4. **Service-Account Relationship Complexity**: Unclear one-to-many vs. one-to-one mapping strategy
5. **Async Processing Gap**: No robust async task system for provisioning operations
6. **Limited Audit Trail**: Insufficient tracking for Romanian compliance requirements

### Business Impact
- **Operational Efficiency**: Manual process delayed customer service activation by hours
- **Data Risk**: Accidental deletions could result in customer data loss
- **Compliance Risk**: Limited audit trails for Romanian hosting regulations
- **Scaling Bottleneck**: Manual process couldn't support projected growth targets

## Decision Drivers

### Business Requirements
- **Automation First**: Eliminate manual intervention in standard provisioning
- **Data Integrity**: Prevent domain conflicts at database level
- **Production Safety**: Implement deletion protection for active accounts
- **Romanian Compliance**: Comprehensive audit trails for regulatory requirements
- **Operational Visibility**: Real-time status tracking and error handling

### Technical Requirements
- **High Availability**: Resilient async processing with retry mechanisms
- **Performance**: Sub-5-minute provisioning for standard hosting accounts
- **Scalability**: Support for 1000+ concurrent provisioning operations
- **Monitoring**: Comprehensive logging and alerting for operational team
- **Future Flexibility**: Architecture supporting business model evolution

### Architectural Constraints
- **Django Monolith**: Maintain existing Django 5.2 architecture
- **PostgreSQL**: Leverage database constraints for data integrity
- **Existing Service Model**: Integrate with current service lifecycle
- **Romanian Context**: Support .ro domains and local hosting compliance

## Considered Options

### Option 1: Manual Provisioning (Current State)
**Approach**: Continue manual VirtualMin account creation by staff

**Pros:**
- ✅ Complete control over provisioning process
- ✅ Flexible handling of edge cases
- ✅ No additional development complexity

**Cons:**
- ❌ High operational overhead (15-30 min per service)
- ❌ Error-prone manual process
- ❌ Cannot scale with business growth
- ❌ Inconsistent configurations
- ❌ No audit trail for compliance

**Verdict:** ❌ **Rejected** - Unsustainable for business growth

### Option 2: Synchronous Automatic Provisioning
**Approach**: Immediate VirtualMin API calls during service activation

**Pros:**
- ✅ Simple implementation
- ✅ Immediate feedback to users
- ✅ No async task complexity

**Cons:**
- ❌ HTTP request timeout risks (VirtualMin API can be slow)
- ❌ Poor user experience during API failures
- ❌ Service activation blocked by VirtualMin issues
- ❌ No retry mechanism for temporary failures
- ❌ Database transactions at risk during external API calls

**Verdict:** ❌ **Rejected** - Unreliable for production use

### Option 3: Asynchronous Automatic Provisioning (Chosen)
**Approach**: Service activation triggers async Django-Q2 provisioning task

**Pros:**
- ✅ Reliable service activation (not blocked by VirtualMin issues)
- ✅ Built-in retry mechanisms for temporary failures
- ✅ Comprehensive error handling and logging
- ✅ Scalable to high-volume operations
- ✅ Separation of concerns between service management and provisioning
- ✅ Production-ready monitoring and alerting capabilities

**Cons:**
- ❌ Additional complexity in async task management
- ❌ Eventually consistent (brief delay between activation and provisioning)
- ❌ Requires monitoring infrastructure for task failures

**Verdict:** ✅ **Accepted** - Best balance of reliability and functionality

### Service-Account Relationship Options

#### Option A: ForeignKey (One-to-Many)
```python
service = models.ForeignKey(Service, related_name="virtualmin_accounts")
```

**Pros:**
- ✅ Supports multiple accounts per service
- ✅ Flexible for complex hosting packages

**Cons:**
- ❌ More complex queries (.filter(), .first() calls)
- ❌ N+1 query potential in list views
- ❌ Doesn't enforce current business logic

#### Option B: OneToOneField (One-to-One) - Chosen
```python
service = models.OneToOneField(Service, related_name="virtualmin_account")
```

**Pros:**
- ✅ Enforces current business logic at database level
- ✅ Direct access via `service.virtualmin_account`
- ✅ More efficient queries and fewer JOINs
- ✅ Clear domain modeling of current requirements

**Cons:**
- ❌ Requires migration if business rules change

**Migration Path Documented**: Clear path to ForeignKey if needed (drop unique constraint)

## Decision

### Core Architecture Decisions

#### 1. Async Provisioning with Django-Q2
**Implementation**: Service status change to "active" triggers async provisioning signal

```python
@receiver(post_save, sender=Service)
def audit_service_lifecycle_events(sender, instance, created, **kwargs):
    if instance.status == "active":
        _trigger_automatic_virtualmin_provisioning(instance)
```

**Benefits:**
- Non-blocking service activation
- Robust retry mechanisms
- Comprehensive error handling
- Production-ready monitoring

#### 2. Database-Level Domain Uniqueness
**Implementation**: Database constraint on VirtualMin account domain field

```python
class VirtualminAccount(models.Model):
    domain = models.CharField(
        max_length=255,
        unique=True,  # Database-level uniqueness
        db_index=True
    )
```

**Benefits:**
- Prevents domain conflicts at database level
- Race condition protection
- Data integrity guarantee

#### 3. OneToOne Service-Account Relationship
**Implementation**: OneToOneField enforcing business logic

```python
service = models.OneToOneField(
    "provisioning.Service",
    on_delete=models.CASCADE,
    related_name="virtualmin_account"
)
```

**Benefits:**
- Enforces current business model
- Efficient database queries
- Clear domain modeling
- Documented migration path for future changes

#### 4. Account Deletion Protection System
**Implementation**: Database flag with UI and API enforcement

```python
protected_from_deletion = models.BooleanField(
    default=True,
    verbose_name="Protected from Deletion"
)
```

**Benefits:**
- Prevents accidental production data loss
- Two-layer protection (UI + backend)
- Audit trail for protection changes

#### 5. Comprehensive Task Architecture
**Implementation**: Django-Q2 tasks with correlation IDs and retry logic

```python
def provision_virtualmin_account_async(params: VirtualminProvisioningParams) -> str:
    return async_task(
        "apps.provisioning.virtualmin_tasks.provision_virtualmin_account",
        params,
        timeout=TASK_TIME_LIMIT
    )
```

**Benefits:**
- Production-ready async processing
- Exponential backoff retry strategy
- Comprehensive audit logging
- Task correlation across systems

## Implementation Details

### Migration Strategy
1. **Database Schema Changes**
   - Add `domain` unique constraint to `VirtualminAccount`
   - Add `protected_from_deletion` field with default `True`
   - Create database indexes for performance optimization

2. **Signal Integration**
   - Implement service status change signal handler
   - Add automatic provisioning trigger logic
   - Integrate with existing audit system

3. **Task System Enhancement**
   - Implement Django-Q2 provisioning tasks
   - Add retry logic with exponential backoff
   - Create task monitoring and alerting

4. **Protection System**
   - Add deletion protection UI components
   - Implement dangerous action modal confirmations
   - Add backend protection validation

### Code Changes Summary
```
Modified Files:
- apps/provisioning/virtualmin_models.py    (+300 lines)
- apps/provisioning/signals.py              (+100 lines)
- apps/provisioning/virtualmin_tasks.py     (+200 lines)
- apps/provisioning/virtualmin_views.py     (+150 lines)
- templates/provisioning/virtualmin/        (+500 lines)

New Features:
- Automatic provisioning on service activation
- Database-level domain uniqueness enforcement
- Account deletion protection system
- Comprehensive async task architecture
- Enhanced UI with protection indicators
```

### Rollback Procedures
1. **Emergency Rollback**: Disable automatic provisioning via Django setting
   ```python
   VIRTUALMIN_AUTO_PROVISIONING_ENABLED = False
   ```

2. **Database Rollback**: Remove unique constraint if conflicts arise
   ```sql
   ALTER TABLE virtualmin_accounts DROP CONSTRAINT virtualmin_accounts_domain_unique;
   ```

3. **Feature Toggle**: UI flag to disable protection system temporarily

### Testing Strategy
- **Unit Tests**: 95% coverage for provisioning logic
- **Integration Tests**: End-to-end provisioning workflows
- **Load Tests**: 1000+ concurrent provisioning operations
- **Failure Tests**: Network failures, timeout scenarios, retry logic

## Consequences

### Positive Outcomes

#### Operational Benefits
- ✅ **Automation**: 90% reduction in manual provisioning time (30min → 3min)
- ✅ **Reliability**: Database constraints prevent domain conflicts
- ✅ **Safety**: Protection system prevents accidental data loss
- ✅ **Scalability**: Async processing supports high-volume operations
- ✅ **Monitoring**: Comprehensive audit trails for Romanian compliance

#### Technical Benefits
- ✅ **Data Integrity**: Database-level constraints and validation
- ✅ **Performance**: OneToOne relationship optimizes queries
- ✅ **Maintainability**: Clear separation between service lifecycle and provisioning
- ✅ **Resilience**: Retry mechanisms handle temporary failures
- ✅ **Observability**: Detailed logging and correlation IDs

### Negative Consequences

#### Complexity Increase
- ❌ **Async Complexity**: Additional task management and monitoring required
- ❌ **State Management**: Eventually consistent system (service active, provisioning pending)
- ❌ **Debugging**: More complex failure scenarios to diagnose
- ❌ **Infrastructure**: Additional monitoring for Django-Q2 tasks required

#### Migration Risks
- ❌ **OneToOne Constraint**: Requires code changes if business model evolves
- ❌ **Domain Conflicts**: Existing duplicate domains require cleanup
- ❌ **Protection Override**: Staff need training on protection system

### Risk Mitigations

#### Technical Mitigations
1. **Task Monitoring**: Real-time Django-Q2 task status dashboard
2. **Failure Alerting**: Immediate notifications for critical provisioning failures
3. **Correlation IDs**: End-to-end tracking for debugging complex scenarios
4. **Rollback Procedures**: Well-documented emergency rollback steps

#### Operational Mitigations
1. **Staff Training**: Comprehensive training on new protection system
2. **Gradual Rollout**: Phase deployment starting with test accounts
3. **Monitoring Period**: 30-day intensive monitoring after production release
4. **Documentation**: Detailed runbooks for common failure scenarios

## Future Considerations

### Business Evolution Support
1. **Multi-Account Migration**: Clear path from OneToOne to ForeignKey relationship
   - Drop unique constraint on `service` field
   - Update all `service.virtualmin_account` references
   - Add filtering logic for multiple accounts

2. **Advanced Features**: Foundation for future enhancements
   - Multi-server load balancing improvements
   - Advanced retry strategies (circuit breakers)
   - Blue-green provisioning for zero-downtime migrations

### Scaling Considerations
1. **High-Volume Processing**: Architecture supports 10,000+ daily provisioning operations
2. **Geographic Distribution**: Ready for multi-region VirtualMin server support
3. **Resource Optimization**: Task queue partitioning for large-scale deployments

### Monitoring and Observability
1. **Metrics Collection**: Provisioning success rates, timing, failure patterns
2. **Alerting Strategy**: Tiered alerts for different failure severities
3. **Business Reporting**: Monthly provisioning statistics for stakeholders

## Implementation Timeline

- **Phase 1** (Week 1): Core provisioning automation and database constraints
- **Phase 2** (Week 2): Protection system and UI enhancements
- **Phase 3** (Week 3): Task monitoring and failure handling improvements
- **Phase 4** (Week 4): Production deployment and intensive monitoring

## Related Decisions

- **ADR-002** (Future): Multi-region VirtualMin deployment strategy
- **ADR-003** (Future): Advanced provisioning patterns for enterprise customers
- **ADR-004** (Future): Integration with Romanian domain registrar APIs

## References

- [Django-Q2 Documentation](https://django-q2.readthedocs.io/)
- PRAHO Service Lifecycle Documentation (planned)
- VirtualMin API Integration Guide (planned)
- Romanian Hosting Compliance Requirements (planned)

---

**Document Version:** 1.0
**Last Updated:** 2025-09-04
**Next Review:** 2025-12-04
**Author:** PRAHO Development Team
