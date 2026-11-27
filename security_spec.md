# Security Specification — Model Academy Auth & Firestore

## Data Invariants
1. **Default Deny**: All paths not explicitly matched are denied for reads and writes.
2. **Owner-Only PII Isolation**: `users/{userId}` can only be read (`get`) or created (`create`) when `request.auth.uid == userId`. Collection listing (`list`) on `users` is strictly denied (`false`).
3. **Role Integrity & No Self-Escalation**: `role` on `users/{userId}` creation is strictly restricted to `['student', 'teacher', 'guardian']`. `'admin'` is forbidden from the client. Updates and deletes on `users/{userId}` are denied (`false`), making `role` immutable.
4. **One Student Account per Class + Roll + ID**: Student registration writes `studentRegistry/{registryKey}` and `users/{userId}` atomically in a batch, verified by `existsAfter(...)`. `studentRegistry` holds no PII (`uid` and `createdAt` only) and disallows `list`, `update`, and `delete`.

## Adversarial Test Payloads ("Dirty Dozen")
1. Unauthenticated read of `/users/uid_1` -> `PERMISSION_DENIED`
2. Authenticated `uid_2` attempting `get` on `/users/uid_1` -> `PERMISSION_DENIED`
3. Authenticated user attempting `list` on `/users` -> `PERMISSION_DENIED`
4. Signup payload setting `role: "admin"` -> `PERMISSION_DENIED`
5. Signup payload with shadow field `isVerified: true` -> `PERMISSION_DENIED`
6. Authenticated owner attempting `update` on `/users/uid_1` to change `role` -> `PERMISSION_DENIED`
7. Signup payload with invalid BD phone `"12345"` -> `PERMISSION_DENIED`
8. Signup payload with client-forged `createdAt` timestamp instead of `request.time` -> `PERMISSION_DENIED`
9. Student signup omitting `studentRegistry/{registryKey}` atomic write -> `PERMISSION_DENIED`
10. Second user attempting to overwrite existing `studentRegistry/{registryKey}` -> `PERMISSION_DENIED`
11. Authenticated user attempting `list` on `/studentRegistry` -> `PERMISSION_DENIED`
12. `studentRegistry` create with spoofed `uid` != `request.auth.uid` -> `PERMISSION_DENIED`
