# Changelog

## Unreleased

### New features

- Added Go-native pxgo proxy implementation with HTTP, HTTPS `CONNECT`, PAC,
  bypass rules, upstream authentication, optional client authentication, and
  Kerberos ticket management.
- Added Go project documentation, sample configuration, icon asset, and Docker
  files at the repository root.

### Internal

- Ported the Python test intent into Go package tests.
- Added race-detector clean synchronization for proxy server startup state and
  Kerberos ticket checks.
