from algopy import Global, GlobalState, Txn, UInt64, subroutine, urange
from algopy.arc4 import Address, Struct, abimethod, emit
from algopy.op import sha256

from ..access_control.contract import AccessControl
from ..types import ARC4UInt64, Bytes32


# Struct
class ScheduledContractUpgrade(Struct):
    program_sha256: Bytes32
    timestamp: ARC4UInt64


class ScheduledDelayUpgrade(Struct):
    delay: ARC4UInt64
    timestamp: ARC4UInt64


# Events
class DelayUpgradeScheduled(Struct):
    delay: ARC4UInt64
    timestamp: ARC4UInt64


class DelayUpgraded(Struct):
    old_delay: ARC4UInt64
    new_delay: ARC4UInt64


class UpgradeScheduled(Struct):
    program_sha256: Bytes32
    timestamp: ARC4UInt64


class UpgradeCancelled(Struct):
    program_sha256: Bytes32
    timestamp: ARC4UInt64


class UpgradeCompleted(Struct):
    program_sha256: Bytes32
    version: ARC4UInt64


# Errors
# ...


class Upgradable(AccessControl):
    delay: UInt64

    def __init__(self) -> None:
        AccessControl.__init__(self)
        self.scheduled_delay_upgrade = GlobalState(ScheduledDelayUpgrade)
        self.scheduled_contract_upgrade = GlobalState(ScheduledContractUpgrade)
        self.version = UInt64(1)

    @abimethod(create="require")
    def create(self, admin: Address, delay: UInt64) -> None:
        self._grant_role(self.default_admin_role(), admin)
        self._grant_role(self.upgradable_admin_role(), admin)

        self._upgrade_delay(delay)

    @abimethod(readonly=True)
    def upgradable_admin_role(self) -> Bytes32:
        return Bytes32.from_bytes(sha256(b"UPGRADABLE_ADMIN"))

    @abimethod(allow_actions=["UpdateApplication"])
    def complete_upgrade(self) -> None:
        """Complete the scheduled upgrade
        Anyone can call this method.

        Raises:
            AssertionError: If the contract SHA256 is not valid
            AssertionError: If the complete upgrade timestamp is not met
        """
        self._check_contract_sha()
        self._check_upgrade_timestamp(
            self.scheduled_contract_upgrade.value.timestamp.native
        )

        self.version += UInt64(1)

        emit(
            UpgradeCompleted(
                self.scheduled_contract_upgrade.value.program_sha256,
                ARC4UInt64(self.version),
            )
        )

        del self.scheduled_contract_upgrade.value

    @abimethod
    def schedule_upgrade_delay(self, delay: UInt64, timestamp: UInt64) -> None:
        """Schedule the upgrade of the delay

        Args:
            delay (UInt64): The new delay
            timestamp (UInt64): The timestamp to schedule the upgrade

        Raises:
            AssertionError: If the caller does not have the upgradable admin role
            AssertionError: If the timestamp is not met
        """
        self._check_role(self.upgradable_admin_role())
        self._check_schedule_upgrade_timestamp(timestamp)

        self.scheduled_delay_upgrade.value.delay = ARC4UInt64(delay)
        self.scheduled_delay_upgrade.value.timestamp = ARC4UInt64(timestamp)

        emit(
            DelayUpgradeScheduled(
                ARC4UInt64(delay), ARC4UInt64(Global.latest_timestamp)
            )
        )

    @abimethod
    def upgrade_delay(self) -> None:
        """Upgrade the scheduled delay
        Anyone can call this method.

        Raises:
            AssertionError: If the delay upgrade is not scheduled
        """
        self._check_upgrade_timestamp(
            self.scheduled_delay_upgrade.value.timestamp.native
        )

        self._upgrade_delay(self.scheduled_delay_upgrade.value.delay.native)

        del self.scheduled_delay_upgrade.value

    @abimethod
    def schedule_upgrade_contract(
        self, program_sha256: Bytes32, timestamp: UInt64
    ) -> None:
        """Schedule the upgrade of the contract

        Args:
            program_sha256 (Bytes32): The SHA256 of the new program
            timestamp (UInt64): The timestamp to schedule the upgrade

        Raises:
            AssertionError: If the caller does not have the upgradable admin role
            AssertionError: If the timestamp is not met
        """
        self._check_role(self.upgradable_admin_role())
        self._check_schedule_upgrade_timestamp(timestamp)

        self.scheduled_contract_upgrade.value.program_sha256 = program_sha256.copy()
        self.scheduled_contract_upgrade.value.timestamp = ARC4UInt64(timestamp)

        emit(UpgradeScheduled(program_sha256.copy(), ARC4UInt64(timestamp)))

    @abimethod
    def cancel_upgrade(self) -> None:
        """Cancel the scheduled upgrade

        Raises:
            AssertionError: If the caller does not have the upgradable admin role
        """
        self._check_role(self.upgradable_admin_role())

        emit(
            UpgradeCancelled(
                self.scheduled_contract_upgrade.value.program_sha256,
                ARC4UInt64(Global.latest_timestamp),
            )
        )

        del self.scheduled_contract_upgrade.value

    @subroutine
    def _upgrade_delay(self, new_delay: UInt64) -> None:
        old_delay = self.delay
        self.delay = new_delay

        emit(DelayUpgraded(ARC4UInt64(old_delay), ARC4UInt64(self.delay)))

    @subroutine
    def _check_schedule_upgrade_timestamp(self, timestamp: UInt64) -> None:
        assert (
            timestamp > self.delay + Global.latest_timestamp
        ), "Schedule upgrade ts not met"

    @subroutine
    def _check_upgrade_timestamp(self, timestamp: UInt64) -> None:
        assert timestamp > Global.latest_timestamp, "Schedule complete ts not met"

    @subroutine
    def _check_contract_sha(self) -> None:
        approval_sha = sha256(b"approval")
        for page_index in urange(Txn.num_approval_program_pages):
            approval_sha = sha256(approval_sha + Txn.approval_program_pages(page_index))

        clear_sha = sha256(b"clear")
        for page_index in urange(Txn.num_clear_state_program_pages):
            clear_sha = sha256(clear_sha + Txn.clear_state_program_pages(page_index))

        assert (
            self.scheduled_contract_upgrade.value.program_sha256
            == Bytes32.from_bytes(sha256(approval_sha + clear_sha))
        ), ("Invalid program SHA256")
