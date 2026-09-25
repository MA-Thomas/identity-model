# Agent instructions — identity-model

Read these before making any code or design change:

1. **[Rust-domain design principles](docs/rust-domain-principles.md)**. They are
   shared by identity-model and cs-mail, are binding, and new work must not regress them.
2. **[Product identity model](../cs-mail/docs/product-identity-model.md)**: subjects,
   product login identities, and Phoros adoption of an existing cs-mail subject
   (in the sibling cs-mail checkout).
3. **[Shared identity contract](docs/shared-identity-contract.md)** and
   **[remaining domain work](RESIDUAL_REFACTOR_DEBT_AND_NEXT_STEPS.md)**.

Working conventions:

- identity-model serves cs-mail now and the Phoros Account later. Treat
  `identity-contract` as an interface consumed by other products.
- cs-mail pins these sources in its `identity-source.sha256`. Commit changes here first,
  then update that manifest in cs-mail.
- Development and testing are local. PostgreSQL suites run with `IDENTITY_DATABASE_URL`
  set to an isolated database.
