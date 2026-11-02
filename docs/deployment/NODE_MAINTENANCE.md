# Customer maintenance windows

Maintenance windows describe planned node work, reserve its execution, and tell affected customers what is happening. They do not grant additional restart, hardening, migration, or cloud permissions. Existing approvals still apply.

Open **Maintenance** from a deployment or Virtualmin server. Administrators and managers can configure the permitted calendar and schedule, move, cancel, start, or finish work. Support can review it. Each change records its actor and reason; stale forms must be reloaded.

## Schedule and perform work

Choose the node's IANA timezone, permitted weekdays and local interval, and latest-start deferral. Overnight intervals belong to their starting weekday. Ambiguous daylight-saving times require an explicit UTC offset; nonexistent local times are refused. Automatic work requires at least one minute of explicitly approved deferral. A missed deadline is recorded as **not run**; the scheduler does not silently extend it.

New policies suggest 15 minutes of deferral for operator review before saving. Existing policies that explicitly specify zero retain zero, and existing window deadlines do not change.

Use a manual window for imported servers and panel updates performed outside the supported adapters. A managed deployment can request a provider reboot. Declare the expected interruption and describe the impact for customers. Automatic patching and automatic security hardening are not window adapters. The existing reviewed hardening workflow retains its separate approval and execution authority; scheduling a window never supplies that approval. Previously stored unsupported automatic modes close as not run without dispatching native work.

Reviewed hardening is performed separately while no maintenance or native operation owns the node. A started manual window does not authorize hardening or bypass its exclusion.

A future schedule does not reserve the server for the entire notice period. Execution claims serialize with account operations, backups/restores, migration/recovery, deployment reservations, teardown and drift. If another operation wins, work may defer until the original latest start. It cannot start late. Independent account operations can continue to coexist.

Provider reboot acceptance is not recovery proof. A reboot window remains running, then overran if necessary, until an authorized operator verifies the recorded target and confirms that commands have stopped. Supported drift recovery verifies provider state and the management connection; it does not claim that every hosted website was tested.

## Emergency recovery

An approved recovery of a server observed powered off creates an immediate emergency window, including on a node without an ordinary calendar. The existing restart approval is still required. Window, exact drift claim and execution ownership commit together before power-on.

An emergency may supersede an **unclaimed future** ordinary window. Its history and any required correction notice are preserved. It cannot preempt current, claimed, issued or uncertain work. If an ordinary window is already due but unclaimed, both claims remain fenced for operator review: review and explicitly cancel the ordinary window, then retry the still-approved recovery. Do not bypass its exclusion by changing database states.

## Recovery and reconciliation

The normal queue publishes one execution owner with its task. Duplicate or delayed payloads cannot replay an issued command. Unissued expired claims may be closed as not run; an issued command, uncertain result or acknowledged reboot never loses its hold merely because time passed or a worker disappeared.

Use the maintenance outcome control for a window. For a direct operation, use **Review node operation** on its server or deployment, including deployments not yet registered as a server. Check the recorded target, confirm commands stopped, provide the actual outcome and a reason. An unissued claim can only be closed as not run. A changed resource identity or stale phase requires further review. Closing a drift execution also fences its exact source job, so a late result cannot change the operator's decision.

## Customer notices

The Portal shows upcoming and active work on affected services and in its shared attention banner. It polls every 30 seconds, including when initially empty. Service ownership is checked for every signed read; company switching changes the scope immediately. Actual execution history keeps the outcome visible when a service moves nodes, for 24 hours after completion. Expired or future completion timestamps are excluded.

Ordinary announcements are due 48 hours before work, or immediately when scheduled later. Work under five minutes without expected downtime is quiet. Emergencies announce immediately and always have an outcome notice. Successful ordinary work within its planned interval has a Portal outcome without a completion email; overruns, failures and announced work that did not run receive the appropriate update. Moving or cancelling an announced window sends a correction, including when the replacement is quiet. Ownership transfers withdraw earlier details from the former recipient rather than disclose the new owner's services.

Notices use the normal encrypted email queue, claim and retry budget. Maintenance follows the customer's service-email preference. Preference, recipient, ownership, placement and revision are rechecked immediately before provider dispatch, including generic retries. A notice already handed to a provider cannot be recalled. Audience history remains available even for customers who opted out or have no email address. A configuration failure retries the same pending intent; it does not create another transport retry system.

Times use the viewer's display timezone. Default notification templates are seeded in Romanian and English; existing operator edits are preserved.

Affected services include current hosting placement and unreleased source mail, DNS, database or authentication responsibilities after a website moves. The staff preview lists these responsibilities separately from accounts currently hosted on the node. Releasing a source responsibility removes it from future notices; an actual maintenance outcome retains its captured audience and current customer ownership checks. A retained responsibility alone does not prohibit maintenance, and finishing maintenance does not release source teardown or backup handoff duties.

The default notices describe a server supporting hosting services, since the website may already run elsewhere. A forward migration updates only pristine defaults and preserves customized templates. Operators maintaining custom notices should review any wording that says the website itself runs on the affected node.

## Deployment and verification

Run the normal migrations. Post-migration setup installs `infra_node_maintenance`, a one-minute Django-Q schedule; `manage.py setup_scheduled_tasks` repairs its registration idempotently. Run the normal queue workers. Keep Platform and Portal versions compatible so signed maintenance reads and banner polling are available together.

`make test-virtualmin-maintenance-portal` runs the actual Platform/Portal HTTP acceptance with owned current-schema fixture databases, local mail and an explicitly scoped worker. It exercises customer switching, notices and manual/emergency outcomes without authorizing provider calls or shared native work. Its screenshots and mail captures are acceptance artifacts, not proof of a provider reboot.

Maintenance windows do not change provider snapshot retention, Platform backups, or customer archive restore policy.
