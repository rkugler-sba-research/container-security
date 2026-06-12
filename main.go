package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const daemonEnv = "GO_DAEMONIZED"

type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte

	Envc uint32
	Env  [10][64]byte
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func daemonize() error {
	if os.Getenv(daemonEnv) == "1" {
		return nil
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnv+"=1")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	f, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}

	cmd.Stdin = f
	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Start(); err != nil {
		return err
	}

	os.Exit(0)
	return nil
}

func main() {
	if err := daemonize(); err != nil {
		log.Fatal(err)
	}

	logFile, err := os.OpenFile(
		"/tmp/env-tracer.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	lnk, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.TraceExecve,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer lnk.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	log.Println("tracing execve env vars...")

	for {
		rec, err := rd.Read()
		if err != nil {
			log.Println("ringbuf error:", err)
			return
		}

		var e Event

		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			continue
		}

		fmt.Printf(
			"\nPID=%d COMM=%s EXEC=%s\n",
			e.Pid,
			cString(e.Comm[:]),
			cString(e.Filename[:]),
		)

		for i := 0; i < int(e.Envc) && i < len(e.Env); i++ {
			env := cString(e.Env[i][:])
			if env != "" {
				fmt.Printf("  ENV: %s\n", env)
			}
		}
	}
}