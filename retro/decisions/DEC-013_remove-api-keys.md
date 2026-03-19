# DEC-013: Remove API Key Auth

- **Date:** 2026-03-18
- **Status:** Decided
- **Context:** API keys were a 4th auth method alongside mTLS, Session JWT, and Bearer JWT. With mTLS added for service-to-service, API keys became redundant — both solve the same use case but mTLS is superior (transport-level, no shared secrets).
- **Decision:** Remove entire API key system (ApiKeyStore, HMAC middleware, CRUD endpoints). Simplify to 3 methods.
- **Consequences:** -1,714 lines deleted. 3 files removed. HMAC + subtle dependencies removed. Auth methods: mTLS → Session JWT → Bearer JWT.
