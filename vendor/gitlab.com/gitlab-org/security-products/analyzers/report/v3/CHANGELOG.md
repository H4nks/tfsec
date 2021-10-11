# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release dates can be found on the [releases page](https://gitlab.com/gitlab-org/security-products/analyzers/vulnerability/-/releases).

## v3.4.0
- Add `location` fields and `Category` for Cluster Image Scanning reports (!14)

## v3.3.0
- Omit `report.Remediations` if empty (!13)

## v3.2.1
- Bump `report.Version` to `v14.0.3` match latest report schema (!12)

## v3.2.0
- Add `tracking` to the vulnerability struct for post-analyzer processing (!10)

## v3.1.0
- Add `flags` to the vulnerability struct for post-analyzer processing (!9)

## v3.0.1
### Fix

- Fix module reference for major version bump (!6)

## v3.0.0
### Removed

- Removed unused WASC identifier support (!5)

## v2.1.0
### Changed

- Change report version from 3.0.0 to 14.0.0 (!4)

## v2.0.0
### Changed

- Rename `Issue` struct to `Vulnerability` (!2)

## v1.0.0
### Added

- Add code for implementing security scanners that generate [GitLab Security reports](https://gitlab.com/gitlab-org/security-products/security-report-schemas) (!1)

