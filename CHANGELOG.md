# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-11-23

### Changed
- Aligned the Entra ID groups query with the `HelloID-SA-Sync-EntraID-Groups-To-Products` sync script, so both scripts behave the same.
- `$entraIDGroupsSearchFilter` is now a `$filter` expression (for example `startswith(displayName,'department_')`) instead of a `$search` expression. It is combined with `and` to the base group filter, and the base group filters are now wrapped in parentheses. Existing `$search=...` values must be converted to a `$filter` expression.

### Fixed
- When the members of an Entra ID group could not be queried (for example due to throttling), the group was treated as empty and all existing productassignments of its product were revoked. Such groups are now skipped, no productassignments are changed for their products, and the task is reported as failed in the summary while all other products are still processed.
- Product ID missing in the error message when querying product actions fails.
- Errors in the final synchronization step are no longer swallowed, the task now ends with an error.
- Corrected remaining references to AD in names and messages (Entra ID).

## [2.1.0] - 2026-05-28

### Changed
- Secret authentication to certificate authentication
- Default correlation changed to `userPrincipalName` and `userName` for linking users.

### Added
- Added support for comment [#2](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-EntraID-Groupmemberships-To-SelfService-Productassignments/issues/2)

## [2.0.2] - 2025-11-06

### Fixed
- Hotfix: removed auditlog for each product

## [1.0.0] - 2023-06-20
Initial commit with base functionality

