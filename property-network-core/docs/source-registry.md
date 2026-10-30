# Source registry and listing provenance

Property Network keeps client acquisition tenancy separate from inventory ownership. A tenant is the relationship owner for the client it acquired; a source is the inventory owner/representative for a listing.

## Registry

The runtime reads a non-secret JSON registry from `SOURCE_REGISTRY_PATH` (default `/data/source-registry.json`). Each source has:

- `sourceId`: stable machine identity, unique across the network.
- `sourceSlug`: stable safe slug for APIs and operator displays.
- `displayName`: human name.
- `ownerTenant`: tenant responsible for the inventory side.
- `adapterType`: neutral adapter identifier.
- `active`: whether the source may contribute inventory.
- `leadRouting`: currently `inventory_owner`; credentials/endpoints are intentionally not stored here.
- `listingTokenStrategy`: identity compatibility mode.
- `legacyDefault`: optional migration bridge for one legacy catalog that predates explicit `sourceId`.

`listingTokenStrategy=legacy_source_url_v1` exists only to preserve already-published listing tokens. New sources should use `source_local_v1`.

The public `/v1/sources` projection excludes token compatibility flags and any future private routing configuration. Credentials, CRM IDs, bot tokens and client data never belong in the registry.

## Normalized listing provenance

Every normalized listing exposed by Property Intent Core includes:

- `sourceId`
- `sourceSlug`
- `sourceLocalId`
- `globalListingId`
- `inventoryOwnerTenant`
- safe `source` metadata
- existing `listingToken`

`globalListingId` is derived from `sourceId + sourceLocalId`, so two sources may use the same display/local `code` without collision. `sourceLocalId` must be unique inside a source. Le Bleu's historical `code` is not unique for four sale/rent pairs, so its compatibility adapter stabilizes `sourceLocalId` with the same canonical-URL hash already embedded in the published legacy token. `sourceUrl` remains a destination/reference field and is never used to infer ownership.

## Routing invariant

Historical `ListingAction` and `OutboundClick` rows are backfilled from their saved listing snapshots even after a listing leaves the live catalog. The registry determines the source owner; the snapshot URL may reproduce a legacy identity hash but never selects ownership by domain.

For every qualified listing intent, persistence records both roles:

1. `tenant` / `networkProvenance.demandTenant` / `relationshipOwnerTenant`: demand-side client relationship owner.
2. `inventory_source_id` / `inventory_owner_tenant`: inventory-side owner.

If both tenants are the same, routing mode is `direct_inventory_owner`. If they differ, routing mode is `collaboration_required`. In the latter state the core does not create a direct owner-side CRM opportunity as if the demand tenant owned the property. The demand-side operator may be notified that collaboration is required, while the intent stays auditable for the later Collaboration layer.

Growth Core and CRM remain soft adapters. They receive safe provenance fields but do not define source ownership.
