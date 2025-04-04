from algopy import ARC4Contract, BoxMap, Txn
from algopy import Bytes, subroutine
from algopy.arc4 import Address, Bool, Struct, abimethod, emit

from ..types import Bytes32

class AddressRoleKey(Struct):
    role: Bytes32
    address: Address

class RoleAdminChanged(Struct):
    role: Bytes32
    prev_admin_role: Bytes32
    new_admin_role: Bytes32

class RoleGranted(Struct):
    role: Bytes32
    account: Address
    sender: Address

class RoleRevoked(Struct):
    role: Bytes32
    account: Address
    sender: Address

class AccessControl(ARC4Contract):
    def __init__(self) -> None:
        self.roles = BoxMap(Bytes32, Bytes32, key_prefix=b"role_")
        self.addresses_roles = BoxMap(AddressRoleKey, Bool, key_prefix=b"address_roles_")

    @abimethod(readonly=True)
    def default_admin_role(self) -> Bytes32:
        return Bytes32.from_bytes(Bytes(b"0000000000000000000000000000000000000000000000000000000000000000"))

    @abimethod(readonly=True)
    def has_role(self, role: Bytes32, account: Address) -> Bool:
        """Returns whether the account has been granted a role

        Args:
            role: The role to check
            account: The account to check

        Returns:
            Whether the account has been granted a role
        """
        return self._has_role(role, account)

    @abimethod(readonly=True)
    def get_role_admin(self, role: Bytes32) -> Bytes32:
        """Returns the admin role that controls a role

        Args:
            role: The role to get its admin of

        Returns:
            The role admin
        """
        return self._get_role_admin(role)

    @abimethod
    def grant_role(self, role: Bytes32, account: Address) -> None:
        """Grant a role to an account

          Args:
              role: The role to grant
              account: The account to grant the role to
          """
        self._check_role(self._get_role_admin(role))
        self._grant_role(role, account)

    @abimethod
    def revoke_role(self, role: Bytes32, account: Address) -> None:
        """Revokes a role from an account

          Args:
              role: The role to revoke
              account: The account to revoke the role from
          """
        self._check_role(self._get_role_admin(role))
        self._revoke_role(role, account)

    @abimethod
    def renounce_role(self, role: Bytes32) -> None:
        """Revokes a role from the caller

          Args:
              role: The role to renounce
          """
        self._revoke_role(role, Address(Txn.sender))

    @subroutine
    def _set_role_admin(self, role: Bytes32, admin_role: Bytes32) -> None:
        previous_role_admin = self._get_role_admin(role)
        self.roles[role] = admin_role.copy()
        emit(RoleAdminChanged(role, previous_role_admin, admin_role))

    @subroutine
    def _address_role_key(self, role: Bytes32, account: Address) -> AddressRoleKey:
        return AddressRoleKey(role.copy(), account)

    @subroutine
    def _has_role(self, role: Bytes32, account: Address) -> Bool:
        address_role_key = self._address_role_key(role, account)
        return self.addresses_roles[address_role_key]

    @subroutine
    def _check_role(self, role: Bytes32) -> None:
        assert self._has_role(role, Address(Txn.sender)), "Sender is missing role"

    @subroutine
    def _get_role_admin(self, role: Bytes32) -> Bytes32:
        assert role in self.roles, "role doesn't exist"
        return self.roles[role]

    @subroutine
    def _grant_role(self, role: Bytes32, account: Address) -> Bool:
        # if new role then add the default admin role
        if role not in self.roles:
            self.roles[role] = self.default_admin_role()

        # grant role to account if it doesn't have
        if not self.has_role(role, account):
            address_role_key = self._address_role_key(role, account)
            self.addresses_roles[address_role_key] = Bool(True)
            emit(RoleGranted(role, account, Address(Txn.sender)))
            return Bool(True)
        else:
            return Bool(False)

    @subroutine
    def _revoke_role(self, role: Bytes32, account: Address) -> Bool:
        # revoke role from account if it does have
        if self.has_role(role, account):
            address_role_key = self._address_role_key(role, account)
            del self.addresses_roles[address_role_key]
            emit(RoleRevoked(role, account, Address(Txn.sender)))
            return Bool(True)
        else:
            return Bool(False)
