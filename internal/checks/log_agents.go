package checks

import (
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// metricsAgents is the one list of agents LOG-004 knows besides the files
// the journal collector looks for. An agent counts when a running container
// uses one of its images or a listening socket belongs to one of its
// processes. Images are repository paths without registry, tag or digest;
// a pattern matches the whole path or its last segments, so "grafana/alloy"
// matches "docker.io/grafana/alloy:v1.4" and "telegraf" matches
// "library/telegraf". Keep docs in internal/catalog/data/log.json in step.
var metricsAgents = []struct {
	name      string
	images    []string
	processes []string
}{
	{"node_exporter", []string{"prom/node-exporter", "prometheus/node-exporter", "bitnami/node-exporter"}, []string{"node_exporter", "prometheus-node-exporter"}},
	{"alloy", []string{"grafana/alloy"}, []string{"alloy"}},
	{"grafana-agent", []string{"grafana/agent", "grafana/agent-operator"}, []string{"grafana-agent"}},
	{"promtail", []string{"grafana/promtail"}, []string{"promtail"}},
	{"netdata", []string{"netdata/netdata"}, []string{"netdata"}},
	{"telegraf", []string{"telegraf"}, []string{"telegraf"}},
	{"vector", []string{"timberio/vector"}, []string{"vector"}},
	{"fluent-bit", []string{"fluent/fluent-bit", "cr.fluentbit.io/fluent/fluent-bit"}, []string{"fluent-bit"}},
	{"datadog-agent", []string{"datadog/agent", "datadog/docker-dd-agent", "datadoghq/agent"}, []string{"datadog-agent"}},
	{"newrelic-infra", []string{"newrelic/infrastructure", "newrelic/infrastructure-bundle"}, []string{"newrelic-infra"}},
	{"zabbix-agent", []string{"zabbix/zabbix-agent", "zabbix/zabbix-agent2"}, []string{"zabbix_agentd", "zabbix_agent2"}},
	{"cadvisor", []string{"cadvisor/cadvisor", "google/cadvisor"}, []string{"cadvisor"}},
	{"beszel-agent", []string{"henrygd/beszel-agent"}, []string{"beszel-agent"}},
}

// imageRepo returns an image reference as a lower case repository path:
// no digest, no tag, no registry host.
func imageRepo(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	if head, rest, ok := strings.Cut(ref, "/"); ok && (strings.ContainsAny(head, ".:") || head == "localhost") {
		ref = rest
	}
	return ref
}

func imageMatches(repo, pattern string) bool {
	return repo == pattern || strings.HasSuffix(repo, "/"+pattern)
}

// containerAgents names the known agents among running containers.
func containerAgents(d *facts.Docker) map[string]string {
	found := map[string]string{}
	if d == nil {
		return found
	}
	for _, c := range d.Containers {
		if !c.Running {
			continue
		}
		repo := imageRepo(c.Image)
		for _, a := range metricsAgents {
			for _, p := range a.images {
				if imageMatches(repo, imageRepo(p)) {
					found[a.name] = c.Name
				}
			}
		}
	}
	return found
}

// processAgents names the known agents that own a listening socket.
func processAgents(l *facts.Listeners) map[string]bool {
	found := map[string]bool{}
	if l == nil {
		return found
	}
	for _, s := range l.Sockets {
		for _, a := range metricsAgents {
			for _, p := range a.processes {
				if s.HasProcess(p) {
					found[a.name] = true
				}
			}
		}
	}
	return found
}

// monitoringAgents merges the three sources (files and units, container
// images, process names) into sorted agent labels: the name, plus where it
// was seen when that was not only on the host's files. names holds the bare
// names for evidence.
func monitoringAgents(f *facts.Facts) (names, labels []string) {
	via := map[string][]string{}
	for _, n := range f.Journal.Agents {
		via[n] = append(via[n], "")
	}
	for n, c := range containerAgents(f.Docker) {
		via[n] = append(via[n], "container "+c)
	}
	for n := range processAgents(f.Listeners) {
		via[n] = append(via[n], "process")
	}
	for n := range via {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var extra []string
		for _, v := range via[n] {
			if v != "" {
				extra = append(extra, v)
			}
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			n += " (" + strings.Join(extra, ", ") + ")"
		}
		labels = append(labels, n)
	}
	return names, labels
}
