package facts

// PaaS is the detected platform (Coolify, Dokploy), its role, proxy and panel (PAAS group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.PaaS is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type PaaS struct{}
