package report

import "testing"

func TestHeadline(t *testing.T) {
	if got := Headline(Item{Title: "No reboot pending", Message: "a reboot is pending"}); got != "a reboot is pending" {
		t.Errorf("with a message: %q", got)
	}
	if got := Headline(Item{Title: "No reboot pending"}); got != "No reboot pending" {
		t.Errorf("without a message: %q", got)
	}
}

func TestNamesSubject(t *testing.T) {
	for _, tc := range []struct {
		msg, subj string
		want      bool
	}{
		{"socket-proxy mounts the Docker socket", "socket-proxy", true},
		{"socket-proxy: mounts it", "socket-proxy", true},
		{"shop-web-1 mounts /etc", "shop/web", false},
		{"socket-proxy-2 mounts it", "socket-proxy", false},
		{"Platform app .env is readable", "tcp/8000", false},
		{"anything", "", false},
	} {
		if got := NamesSubject(tc.msg, tc.subj); got != tc.want {
			t.Errorf("NamesSubject(%q, %q) = %v, want %v", tc.msg, tc.subj, got, tc.want)
		}
	}
}

func TestShortSubject(t *testing.T) {
	for in, want := range map[string]string{
		"host": "", "": "", "container:app/web": "app/web", "port:tcp/22": "tcp/22", "plain": "plain",
	} {
		if got := ShortSubject(in); got != want {
			t.Errorf("ShortSubject(%q) = %q, want %q", in, got, want)
		}
	}
}
