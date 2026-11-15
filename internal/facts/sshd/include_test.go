package sshd

import (
	"reflect"
	"testing"
)

func TestIncludesAreRecorded(t *testing.T) {
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config":                      "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nMatch User alice\n  Include extra/*.conf\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "Include nested.conf\nPasswordAuthentication yes\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	want := []Include{
		{Pattern: "/etc/ssh/sshd_config.d/*.conf", File: "/etc/ssh/sshd_config", Line: 1},
		{Pattern: "/etc/ssh/nested.conf", File: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Line: 1},
		{Pattern: "/etc/ssh/extra/*.conf", File: "/etc/ssh/sshd_config", Line: 4, Match: 1},
	}
	if !reflect.DeepEqual(c.Includes, want) {
		t.Fatalf("includes = %+v\nwant %+v", c.Includes, want)
	}
}
