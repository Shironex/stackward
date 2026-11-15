package allowedfs

import (
	"os"
	"os/exec"
)

func ok() {
	_ = os.WriteFile("a", nil, 0o600) // allowed: FSWrite
}

func notOk() {
	_ = exec.Command("ls") // want `os/exec.Command starts a program`
}
