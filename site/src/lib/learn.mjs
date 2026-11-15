// The Learn track in reading order. The sidebar, the "start here" path, the
// step counter on each topic and the "learn more" links on check pages all
// read this list, so a topic is added in one place.
//
// `checks` are the catalog ids a topic explains. Ids that are not in the
// catalog yet render as planned, and link up on their own once the check
// lands in internal/catalog/data/.

/** @typedef {{ slug: string, title: string, short: string, summary: string, phase: string, minutes: number, checks: string[] }} Topic */

/** The phases of the path, in order. Each topic belongs to one. */
export const PHASES = [
  { id: 'access', title: 'Keep the door shut', text: 'Who can log in, and how.' },
  { id: 'exposure', title: 'Know what is exposed', text: 'What Docker and the network really let through.' },
  { id: 'defence', title: 'Layers in front', text: 'The ways in, and what stops abuse at them.' },
  { id: 'hygiene', title: 'Keep the host healthy', text: 'Patches, kernel settings and the secrets on disk.' },
  { id: 'proof', title: 'Platform and proof', text: 'Platform specifics, then checking it all from outside.' },
];

/** @type {Topic[]} */
export const TOPICS = [
  {
    slug: 'ssh',
    phase: 'access',
    minutes: 9,
    title: 'SSH access',
    short: 'SSH access',
    summary: 'Passwords, root login, the effective config and why the first value wins.',
    checks: ['SSH-001', 'SSH-002', 'SSH-003', 'SSH-004', 'SSH-005', 'SSH-006', 'SSH-008', 'SSH-009', 'SSH-010', 'SSH-011', 'SSH-013', 'SSH-014'],
  },
  {
    slug: 'firewall-and-docker',
    phase: 'exposure',
    minutes: 10,
    title: 'The firewall, and how Docker walks past UFW',
    short: 'Firewall and Docker',
    summary: 'Why a UFW deny rule does not close a published container port.',
    checks: ['NET-001', 'NET-002', 'NET-004', 'NET-006', 'NET-007', 'NET-008', 'DKR-001', 'DKR-033'],
  },
  {
    slug: 'docker-socket',
    phase: 'exposure',
    minutes: 8,
    title: 'The Docker socket',
    short: 'Docker socket',
    summary: 'Whoever can talk to the Docker daemon controls the host.',
    checks: ['DKR-002', 'DKR-003', 'DKR-010', 'DKR-011', 'USR-005'],
  },
  {
    slug: 'containers-as-root',
    phase: 'exposure',
    minutes: 8,
    title: 'Containers that run as root',
    short: 'Containers as root',
    summary: 'Root in a container, privileged mode, capabilities and host mounts.',
    checks: ['DKR-020', 'DKR-021', 'DKR-022', 'DKR-023', 'DKR-024', 'DKR-012'],
  },
  {
    slug: 'docker-networks',
    phase: 'exposure',
    minutes: 6,
    title: 'Shared Docker networks',
    short: 'Shared networks',
    summary: 'One network for every project means one breach reaches every database.',
    checks: ['DKR-030', 'PAAS-005'],
  },
  {
    slug: 'private-ingress',
    phase: 'defence',
    minutes: 10,
    title: 'Tailscale and tunnels as the only way in',
    short: 'Tunnels and Tailscale',
    summary: 'Close the origin, keep a private path, and prove it still works.',
    checks: ['TS-001', 'TS-002', 'TS-003', 'TS-004', 'CF-002', 'CF-003', 'NET-003', 'NET-005', 'PAAS-002'],
  },
  {
    slug: 'crowdsec-and-fail2ban',
    phase: 'defence',
    minutes: 9,
    title: 'CrowdSec and fail2ban behind a tunnel',
    short: 'CrowdSec and fail2ban',
    summary: 'Why a firewall ban does nothing when every request arrives from the tunnel.',
    checks: ['CS-001', 'CS-002', 'CS-003', 'CS-004', 'CS-005', 'CS-008', 'CS-010', 'CS-011'],
  },
  {
    slug: 'updates',
    phase: 'hygiene',
    minutes: 7,
    title: 'Unattended upgrades and end of support',
    short: 'Updates',
    summary: 'Patches that are installed but not running, and releases nobody patches.',
    checks: ['UPD-001', 'UPD-002', 'UPD-003', 'UPD-004', 'UPD-005', 'UPD-006', 'SYS-002', 'SYS-003'],
  },
  {
    slug: 'kernel-settings',
    phase: 'hygiene',
    minutes: 8,
    title: 'Kernel settings that protect, and settings that break',
    short: 'Kernel settings',
    summary: 'sysctl values worth setting, and the hardening profile that breaks Docker.',
    checks: ['KRN-001', 'KRN-002', 'KRN-003', 'KRN-004', 'KRN-005'],
  },
  {
    slug: 'secrets-on-disk',
    phase: 'hygiene',
    minutes: 7,
    title: 'Secrets on disk',
    short: 'Secrets on disk',
    summary: 'File permissions on .env files, keys and registry credentials.',
    checks: ['SEC-001', 'SEC-002', 'SEC-003', 'SEC-005', 'SEC-006', 'CF-004'],
  },
  {
    slug: 'coolify-and-dokploy',
    phase: 'proof',
    minutes: 9,
    title: 'Coolify and Dokploy specifics',
    short: 'Coolify and Dokploy',
    summary: 'Panel ports, public databases, the proxy, Swarm ports and keys.',
    checks: ['PAAS-001', 'PAAS-002', 'PAAS-003', 'PAAS-004', 'PAAS-006', 'PAAS-008', 'SEC-003', 'SEC-004'],
  },
  {
    slug: 'outside-view',
    phase: 'proof',
    minutes: 6,
    title: 'The outside view with probe',
    short: 'The outside view',
    summary: 'Some things can only be seen from another machine.',
    checks: ['PRB-001', 'PRB-002', 'PRB-003', 'PRB-004', 'PRB-005', 'PRB-006', 'NET-009', 'CF-005'],
  },
];

/** Topics that explain a check id, in reading order. */
export function topicsForCheck(id) {
  return TOPICS.filter((topic) => topic.checks.includes(id));
}
