# Collaboration and demand exchange model

This is the next domain layer after tenant isolation. It is deliberately smaller than a CRM.

## Problem

A network agency may have a qualified buyer/tenant demand that another participating source can satisfy. The platform must enable matching and controlled collaboration without losing source ownership, exposing private client data too early, or making attribution impossible.

## Demand card

A demand card is a structured, privacy-minimized representation of a real client need. Suggested fields:

- `id`
- `tenant`
- `created_by_actor`
- `operation` (`Venta` / `Alquiler`)
- `property_types[]`
- `neighborhoods[]`
- `budget_currency`, `budget_min`, `budget_max`
- `rooms`, `min_bedrooms`, `min_bathrooms`, `min_area_m2`
- `required_features[]`
- `move_or_purchase_window`
- `qualification_level`
- `notes_public`
- `status` (`draft`, `active`, `matched`, `paused`, `closed`)
- timestamps

Do not put the client's phone, email, full name, passport, financial documents or private chat transcript in the network-visible card.

## Match

A match links a demand card to a source-bound listing and stores:

- demand owner tenant
- inventory source / listing token
- match method (`manual`, `rule`, `system_suggested`)
- match score/reasons
- state (`suggested`, `shared`, `accepted`, `rejected`, `viewing`, `reserved`, `won`, `lost`)
- collaboration owner and timestamps

## Collaboration record

The collaboration record is the auditable handshake between the demand-side tenant and the inventory-side source/tenant. It must be idempotent and preserve:

- who introduced the demand
- who owns/represents the inventory
- when access was requested/accepted
- commercial terms reference if any
- lead/deal attribution IDs
- lifecycle events

Commercial percentages or commission terms should not be inferred from platform defaults. They belong to an explicit agreement/reference per collaboration or partner relationship.

## Privacy gate

1. Before acceptance: only structured demand, no direct client contact.
2. After accepted collaboration: disclose only the minimum contact/context required by the agreed workflow.
3. Every disclosure is audited.
4. Revoking/closing a demand stops further matching but preserves audit history.

## Routing invariant

A listing lead must never silently bypass the inventory/source owner. A demand-side tenant may remain the relationship owner for its client while the inventory-side party remains the property-side owner. Downstream events retain both roles.

## MVP scope

First MVP should support manual demand creation, deterministic catalog matching and explicit accept/reject collaboration. Do not build chat, payments, commission settlement or a generalized social network before this loop is proven with real agencies.
