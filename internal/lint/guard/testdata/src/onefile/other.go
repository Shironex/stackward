package onefile

import "os/exec"

func other() { _ = exec.Command("ls") } // want `os/exec.Command starts a program`
