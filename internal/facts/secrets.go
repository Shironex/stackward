package facts

// Secrets is file metadata (mode, owner, group) of secret bearing files. Contents are never read (SEC group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Secrets is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Secrets struct{}
