# Property Network Core

Canonical source tree for the neutral real-estate network evolving from the Le Bleu production pilot.

## Boundaries

- `services/property-intent`: tenant-aware domain core for catalog discovery, saved searches, explicit notifications, listing actions and attribution events.
- `apps/miniapp`: consumer catalog UI. Branding and acquisition surfaces must come from tenant configuration, not source-code forks.
- `adapters/lebleu-listing`: Le Bleu-specific inventory and Telegram publishing adapter. It is a pilot adapter, not a dependency of the neutral core.
- Growth Core and agency CRMs remain external services reached through contracts/adapters.

## Production safety

Le Bleu remains the live pilot tenant until an explicit public cutover. Neutralization must be backward-compatible: the same Le Bleu configuration should render the current product while another tenant can be instantiated without editing application source.
