package facts

// Users is accounts, sudoers and docker group membership (USR group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Users is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Users struct{}
