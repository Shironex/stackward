package guard

// forbidden maps the full name of a function or method (types.Func.FullName)
// to the category of side effect it has. os.OpenFile is handled separately,
// because only some flag sets write.
var forbidden = map[string]Category{}

func init() {
	add := func(c Category, names ...string) {
		for _, n := range names {
			forbidden[n] = c
		}
	}
	add(FSWrite,
		"os.WriteFile", "os.Create", "os.CreateTemp", "os.Remove", "os.RemoveAll",
		"os.Rename", "os.Mkdir", "os.MkdirAll", "os.MkdirTemp", "os.Chmod",
		"os.Chown", "os.Lchown", "os.Symlink", "os.Link", "os.Truncate",
		"os.Chtimes",
		"io/ioutil.WriteFile", "io/ioutil.TempFile", "io/ioutil.TempDir",
		"syscall.Unlink", "syscall.Rmdir", "syscall.Rename", "syscall.Mkdir",
		"syscall.Chmod", "syscall.Chown", "syscall.Lchown", "syscall.Symlink",
		"syscall.Link", "syscall.Truncate", "syscall.Mknod",
		"golang.org/x/sys/unix.Unlink", "golang.org/x/sys/unix.Unlinkat",
		"golang.org/x/sys/unix.Rmdir", "golang.org/x/sys/unix.Rename",
		"golang.org/x/sys/unix.Renameat", "golang.org/x/sys/unix.Mkdir",
		"golang.org/x/sys/unix.Mkdirat", "golang.org/x/sys/unix.Chmod",
		"golang.org/x/sys/unix.Fchmodat", "golang.org/x/sys/unix.Chown",
		"golang.org/x/sys/unix.Fchownat", "golang.org/x/sys/unix.Symlink",
		"golang.org/x/sys/unix.Link", "golang.org/x/sys/unix.Truncate",
		"golang.org/x/sys/unix.Mknod",
	)
	add(Exec,
		"os/exec.Command", "os/exec.CommandContext", "os.StartProcess",
		"syscall.Exec", "syscall.ForkExec", "syscall.StartProcess",
		"golang.org/x/sys/unix.Exec",
	)
	add(Net,
		"net.Dial", "net.DialTimeout", "net.DialTCP", "net.DialUDP",
		"net.DialIP", "net.DialUnix", "net.Listen", "net.ListenTCP",
		"net.ListenUDP", "net.ListenIP", "net.ListenUnix",
		"net.ListenUnixgram", "net.ListenPacket",
		"net.LookupHost", "net.LookupIP", "net.LookupAddr", "net.LookupCNAME",
		"net.LookupMX", "net.LookupNS", "net.LookupSRV", "net.LookupTXT",
		"net.LookupPort",
		"(*net.Dialer).Dial", "(*net.Dialer).DialContext",
		"(*net.ListenConfig).Listen", "(*net.ListenConfig).ListenPacket",
		"(*net.Resolver).LookupHost", "(*net.Resolver).LookupIPAddr",
		"(*net.Resolver).LookupAddr", "(*net.Resolver).LookupCNAME",
		"(*net.Resolver).LookupMX", "(*net.Resolver).LookupNS",
		"(*net.Resolver).LookupSRV", "(*net.Resolver).LookupTXT",
		"(*net.Resolver).LookupNetIP",
		"crypto/tls.Dial", "crypto/tls.DialWithDialer", "crypto/tls.Listen",
		"(*crypto/tls.Dialer).Dial", "(*crypto/tls.Dialer).DialContext",
		"net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm",
		"net/http.ListenAndServe", "net/http.ListenAndServeTLS",
		"(*net/http.Client).Do", "(*net/http.Client).Get",
		"(*net/http.Client).Head", "(*net/http.Client).Post",
		"(*net/http.Client).PostForm",
		"(*net/http.Transport).RoundTrip",
		"(*net/http.Server).ListenAndServe",
		"(*net/http.Server).ListenAndServeTLS", "(*net/http.Server).Serve",
	)
	add(RawSyscall,
		"syscall.Syscall", "syscall.Syscall6", "syscall.RawSyscall",
		"syscall.RawSyscall6", "syscall.AllThreadsSyscall",
		"syscall.AllThreadsSyscall6",
		"golang.org/x/sys/unix.Syscall", "golang.org/x/sys/unix.Syscall6",
		"golang.org/x/sys/unix.RawSyscall", "golang.org/x/sys/unix.RawSyscall6",
	)
}

// describe says what a category means in a finding.
var describe = map[Category]string{
	FSWrite:    "writes to the filesystem",
	Exec:       "starts a program",
	Net:        "uses the network",
	RawSyscall: "makes a raw system call",
}
