package facts

// Tailscale is Tailscale backend state, key expiry, serve and funnel (TS group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Tailscale is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Tailscale struct{}
