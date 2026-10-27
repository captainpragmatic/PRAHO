"""Full production setup/replay/reboot contract on each explicitly selected clean node image."""

import pytest

from tests.virtualmin_mail_lab.harness import MailClone


@pytest.mark.mail_node
def test_production_mail_capability_keeps_unenrolled_accounts_off_across_reboot(mail_clone: MailClone) -> None:
    mail_clone.prepare()
    mail_clone.playbook("setup")
    mail_clone.node("preserved")
    mail_clone.playbook("setup")  # Ready replay must preserve the same pre-setup customer controls.
    mail_clone.node("preserved")
    mail_clone.node("new_default")
    mail_clone.node("denied")
    mail_clone.playbook("reconcile_submitters")
    mail_clone.node("preserved")
    mail_clone.reboot()
    mail_clone.playbook("inspect_node")  # Fresh production inspection, not a pre-reboot receipt.
    mail_clone.node("denied")
    mail_clone.node("preserved")
