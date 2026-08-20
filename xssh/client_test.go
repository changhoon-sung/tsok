package xssh

import "testing"

func TestRemoteCommand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{name: "shell"},
		{name: "single argument", args: []string{"uname"}, want: "uname", ok: true},
		{name: "multiple arguments", args: []string{"uname", "-a"}, want: "uname -a", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := remoteCommand(tc.args)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("remoteCommand(%q) = %q, %v; want %q, %v", tc.args, got, ok, tc.want, tc.ok)
			}
		})
	}
}
