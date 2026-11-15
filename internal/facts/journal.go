package facts

// Journal is journald size and persistence settings (LOG group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Journal is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Journal struct{}
