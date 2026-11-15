package onefile

import "os/exec"

func ok() { _ = exec.Command("ls") }
