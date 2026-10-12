# Changelog

All notable changes to the OpenFlux core. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- **Mail.ru Docs exit sessions no longer die with `close 1005` seconds after auth.** Mail.ru closes
  "editor" document participants that never send document activity; the transport now sends a
  `saveChanges` editor-activity message every random 0.5-5 s (the same one the web editor sends),
  skipped when the link cannot edit (`canEdit(permissions)`) — a read-only link that saves gets the
  socket cut immediately. Adopted together with upstream's cursor fixes (every cursor entry of a
  batched server message now comes out, keep-alives anywhere in the batch no longer cost the data
  around them), the keep-alive loop that closes the socket on write failure, and the reconnect
  fixes (a scheduled reconnect already waiting out its backoff makes a second one a no-op).
