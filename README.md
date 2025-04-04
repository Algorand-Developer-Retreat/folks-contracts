# Folks Contracts

## Overview

**Reusable interface patterns for Python Algorand smart contracts.**

This library aims to reduce development time, minimize security risks, and establish standardized interfaces for common smart contract functionality.

## Contracts

### Available

### AccessControl

The `AccessControl` contract provides a role-based permission system. It enables granular access control through hierarchical roles, allowing different addresses to perform specific actions based on their assigned roles.

Reference: [OpenZeppelin AccessControl](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol)

### Structure Guidelines

For consistency across the ecosystem, we recommend the following structure and order

- `Imports`
- `Struct`
  - `Global`
  - `Local`
  - `Box`
- `Events`
- `Errors`

- `Contract`
  - `constructor`: _create_
  - `public` _readonly_
  - `public` _allow_actions_
  - `public`
  - `internal` _subroutine_
