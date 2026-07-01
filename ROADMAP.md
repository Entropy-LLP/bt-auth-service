# bt-auth-service — Development Roadmap

> **Part of [BharatTruck](https://github.com/CodeMongerrr/LogisticOS-pathway).** Owns **Identity, Roles & KYC** (PRD §5.1). Master PRD lives in `LogisticOS-pathway/docs/BHARATTRUCK_MVP_PRD.md`.
> **MVP deadline:** 31 Aug 2026 · **North Star:** Completed Paid Trips · _Living doc — update the checkboxes as work lands._

**Role:** Authentication + the truck-derived role model (Driver ↔ Fleet Owner) + KYC gating for every paying actor and every working truck.

**Status legend:** ✅ done · 🟡 partial/in-progress · ⬜ to do · ⛔ stub/blocked

---

## ✅ What's done
- ✅ Custom JWT auth (access + refresh, HS256), refresh-token revocation via Redis.
- ✅ Four auth methods coexist: email+password (bcrypt cost 12), email magic-link, Google OAuth (account-linking by google_sub→email), phone OTP **(skeleton)**.
- ✅ Redis as source of truth for OTPs, magic-link single-use tokens, OTP rate-limiting (5/hr).
- ✅ Onboarding routes scaffolded (12 endpoints).
- ✅ PII crypto helpers: AES-256-GCM for Aadhaar/PAN/bank numbers + SHA-256 `hashForLookup` for duplicate detection.
- ✅ KYC module structure laid out: 9 verification files (aadhaar, pan, dl, rc, gst, bank, face-match, phone, email), 4-tier level model (L0–L3) designed.

## ⛔ Stubbed / not functional yet
- ⛔ **All KYC verify endpoints return 501** (`POST /kyc/verify/:type`, `GET /kyc/status/:userId`).
- ⛔ SurePass client (`lib/surepass.ts`) `.post()` throws "not implemented" — zero real KYC calls possible.
- ⛔ Fraud checks (duplicate Aadhaar/PAN, fuzzy name match) throw "not implemented".
- ⛔ KYC repository (`getKYCRecord`/`upsertVerification`) throws; `getCurrentLevel` hardcodes L0 → level gating can't be enforced.
- ⛔ Phone OTP is never sent — only `console.log`'d (no MSG91/Twilio code despite README).

## ⬜ To do (MVP / P0)
- ⬜ Implement SurePass calls: **PAN, Aadhaar (v2 two-step OTP), RC/Vahan, DL (enforce HMV/HTV class), bank penny-drop, face-match** (70% threshold, 50–70% → manual review).
- ⬜ Persist KYC records (JSONB `verifications` on `user_kyc`) + enforce **L0–L3 gating** (booking at L1, payouts at L3).
- ⬜ **Truck-derived role model:** truck CRUD (add by RC → Vahan verify), 1 truck = Driver, 2+ = Fleet Owner; fully migratable; same person can be both.
- ⬜ **Fleet ↔ driver affiliation:** fleet owner adds affiliated drivers, assigns a fleet truck to a driver (reflects in driver app). Truck need NOT be in user's name — verify truck authenticity only.
- ⬜ **Shipper KYC** required only when order value > ₹50,000.
- ⬜ Wire **MSG91** for real phone OTP.
- ⬜ Fix `POST /auth/register` silently dropping `truck_type/truck_number/license_number`.
- ⬜ Add KYC authorization guard (requester == userId or admin).
- ⬜ Add `ENCRYPTION_KEY` to `.env.example` + README (currently required by code but undocumented → 500 on fresh deploy).
- ⬜ Reconcile role enums (auth uses `shipper|driver|fleet_owner`; KYC uses `CUSTOMER|DRIVER|FLEET_OPERATOR`).
- ⬜ Manual KYC approval is done via **bt-ops-web** console — expose the queue/approve/reject API it needs.

## 🔮 Deferred / out of MVP
- Supabase Auth migration — **keep custom JWT for MVP** (it works); migrate post-pilot.
- Signzy (we standardized on SurePass only).
- Driver ratings (Fleet-owner reviews only at MVP).

## 🔑 External dependencies / data
- **SurePass** account + API key, with **Aadhaar API enabled** (often gated behind business verification) + credits.
- **MSG91** account for OTP/SMS.

## 🎯 Definition of done (this service)
A new user signs up → adds a truck by RC → Vahan-verifies it → completes PAN+Aadhaar+bank KYC → is **manually approved by ops** → shows "Verified" + can bid. Adding a 2nd truck flips to Fleet Owner; assigning a fleet truck to a driver reflects in that driver's app. Shipper >₹50k is blocked until shipper-KYC clears.

_Last updated: 2026-07-01_
