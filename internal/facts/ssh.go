package facts

// SSH is the effective OpenSSH server configuration, its listeners and key files (SSH group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.SSH is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type SSH struct{}
