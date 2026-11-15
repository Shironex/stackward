package facts

// Disk is filesystem usage of /, /var and the Docker root (SYS-005).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Disk is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Disk struct{}
