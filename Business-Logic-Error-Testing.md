# Business Logic Error Testing Methodology

Goal: identify flaws in application workflows and assumptions that allow abuse even when technical controls are correct.

## Mindset & quick checks

* Map full user journeys (registration, checkout, refunds, password reset, invite flows).
* Look for assumptions: unique constraints, invariants, sequence numbers, single-use tokens, rate limits, idempotency.
* Think like a user trying to get more value: free purchases, double refunds, escalate privileges, bypass payment.

## Common test cases

* **Price manipulation**: alter client-side price, currency, quantity, or order details before sending to server.
* **Coupon / discount abuse**: reuse single-use coupons, stack coupons, apply negative discounts.
* **Authorization logic gaps**: perform actions across accounts by changing IDs in requests (IDOR-like but business focused).
* **Race conditions**: perform concurrent requests to buy limited stock or redeem codes multiple times.
* **Workflow bypass**: skip verification steps (confirmations, 2FA) by resubmitting earlier requests or modifying state.
* **Refund/Chargeback abuse**: cancel after delivery, trigger refunds without validation.
* **Payment gateway issues**: change `amount` in client requests or manipulate callback parameters.
* **Inventory manipulation**: modify order status to `shipped` or `delivered` to trigger refunds or re-order flows.

## Example test vectors

```
- Send two simultaneous POST /redeem with same code.
- POST /order {"price":0,"items":[...]}
- Modify basket cookie to increase loyalty points.
- Use API to change order status: PATCH /orders/{id} {"status":"cancelled"}
```

## Testing steps

1. Enumerate business endpoints and map state transitions.
2. Identify client-side logic that enforces business rules (JS, mobile app logic) and replicate/modify server requests.
3. Attempt to change any server-trusted values from client (price, role, quantity, isGift, shippingCost).
4. Try concurrent actions to detect race conditions (automate with Burp or scripts).
5. Test multi-step flows where tokens or one-time-use values are accepted more than once.
6. Check for missing validation on webhook/callback endpoints from payment providers.

## Reporting checklist

* Describe the normal flow and how you deviated from it.
* Exact requests used and a concise impact description (money loss, privilege escalation, bypass).
* Steps to reproduce.
* Suggested mitigations: server-side validation of all critical values, idempotency keys, proper transaction handling, rate-limiting, audit logs.

---

