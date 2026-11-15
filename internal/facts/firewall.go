package facts

// Firewall is the host firewall state: UFW, nftables, iptables, DOCKER-USER and ufw-docker (NET group).
//
// Placeholder: the collector that owns this type has not landed yet, so
// Facts.Firewall is always nil and every check that needs it returns unknown.
// The owning slice replaces this struct and adds its collector in this
// file (see docs/architecture.md, "Add a collector").
type Firewall struct{}
