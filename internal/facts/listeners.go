package facts

// Listeners is every listening socket with its bind address and owning process (NET-004 and exposure).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Listeners is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Listeners struct{}
