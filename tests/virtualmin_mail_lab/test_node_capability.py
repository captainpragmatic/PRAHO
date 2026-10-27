"""Full production setup/replay/reboot contract on each explicitly selected clean node image."""

from uuid import uuid4

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
    rotation_id = uuid4()
    mail_clone.certificate_candidate("wrong_name")
    assert mail_clone.playbook("reconcile_node_certificate", operation_id=rotation_id)["outcome"] == "retained_previous"
    mail_clone.node("certificate_unchanged")
    mail_clone.certificate_candidate("valid")
    assert mail_clone.playbook("reconcile_node_certificate", operation_id=rotation_id)["outcome"] == "replaced"
    mail_clone.node("certificate_replaced")
    mail_clone.node("preserved")
    # Another native renewal cannot cause a completed delivery to replace the service copy.
    mail_clone.certificate_candidate("valid")
    assert mail_clone.playbook("reconcile_node_certificate", operation_id=rotation_id)["outcome"] == "unchanged"
    mail_clone.node("certificate_unchanged")
    second = mail_clone.playbook("reconcile_node_certificate")
    assert second["outcome"] == "replaced"
    mail_clone.node("certificate_replaced")
    delayed = mail_clone.playbook("reconcile_node_certificate", operation_id=rotation_id)
    assert delayed["outcome"] == "unchanged"
    assert delayed["certificate_sha256"] == second["certificate_sha256"]
    mail_clone.node("preserved")
    mail_clone.node("denied")
    mail_clone.playbook("reconcile_submitters")
    mail_clone.node("preserved")
    mail_clone.reboot()
    mail_clone.playbook("inspect_node")  # Fresh production inspection, not a pre-reboot receipt.
    mail_clone.node("denied")
    mail_clone.node("preserved")
