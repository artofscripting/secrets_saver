# Contributing

## Security Rules For Examples And Tests

- Never hardcode master keys, passphrases, or encryption passwords in source files.
- This applies to all examples, READMEs, test scripts, and unit tests.

### Required Patterns

Use one of these patterns instead:

1. Interactive prompt at runtime.
2. Runtime-provided environment variable (for CI/non-interactive runs).
3. Runtime-generated ephemeral value for unit tests.

### Do And Do Not

- Do: prompt users for the master key on first access.
- Do: inject a key at runtime via environment variable for automation.
- Do: generate unique test keys dynamically during test execution.
- Do not: commit literal keys such as `test-pass`, `good-pass`, or similar strings.

## File Extension Convention

- The default encrypted file extension is `.ep`.
- Do not introduce `.db` examples for encrypted file payloads.
