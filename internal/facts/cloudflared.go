package facts

// Cloudflared is Cloudflare Tunnel connectors found as containers or services (CF group). Token values are never stored.
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Cloudflared is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Cloudflared struct{}
