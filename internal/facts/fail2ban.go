package facts

// Fail2ban is fail2ban jails and ignoreip (CS-010, CS-011).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Fail2ban is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Fail2ban struct{}
