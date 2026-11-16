package fleet

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// sshOptions are forced on every connection, on top of the user's ssh
// config, which still decides the user, port, keys, jump hosts and known
// hosts:
//
//   - BatchMode: never prompt (stackward never sees a password or a
//     passphrase, and parallel prompts could not be answered anyway); an
//     unknown host key fails instead of being accepted;
//   - no agent or X11 forwarding and no port forwards from the config: the
//     audited host gets nothing back from this machine;
//   - no TTY: the binary arrives on standard input and the report leaves on
//     standard output, byte for byte.
var sshOptions = []string{
	"-T", "-a", "-x",
	"-o", "BatchMode=yes",
	"-o", "ClearAllForwardings=yes",
	"-o", "ConnectTimeout=15",
}

// sshWaitDelay bounds how long the pipes may stay open after ssh exits or
// the context ends. A ControlMaster with ControlPersist started by this
// ssh call can keep standard error open after ssh itself has exited; the
// output is complete by then, so the pipes are closed after this delay and
// the exit code counts (a variable so tests can shorten it).
var sshWaitDelay = 5 * time.Second

// runSSH runs `ssh <options> -- host remote` with the user's own ssh client,
// found on PATH, without a local shell. host has passed ValidateHost and
// remote is one of this package's fixed commands. It returns the exit code
// of ssh (the remote command's, or 255 when ssh itself failed); err is set
// when ssh could not be started or was stopped by ctx.
func runSSH(ctx context.Context, host, remote string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	args := make([]string, 0, len(sshOptions)+3)
	args = append(args, sshOptions...)
	args = append(args, "--", host, remote)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.WaitDelay = sshWaitDelay
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}
