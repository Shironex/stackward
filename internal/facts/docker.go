package facts

// Docker is what the Docker Engine API answers over the Unix socket, GET only, with Config.Env and Cmd stripped before parsing (DKR group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Docker is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Docker struct{}
