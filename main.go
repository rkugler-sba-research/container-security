package main

import (
	"bytes"
	"encoding/binary"
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
	//Argc uint32
	//Args [10][64]byte
}

func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
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

	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

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
		"/var/log/exec-tracer.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	log.Printf("exec-tracer started pid=%d", os.Getpid())

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.TraceExecve,
		nil,
	)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("tracing execve events")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("ringbuf read error: %v", err)
				return
			}

			var e Event

			if err := binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				&e,
			); err != nil {
				log.Printf("decode event: %v", err)
				continue
			}
			/*
			args := make([]string, 0, e.Argc)

			for i := 0; i < int(e.Argc) && i < len(e.Args); i++ {
				arg := cString(e.Args[i][:])
				if arg != "" {
					args = append(args, arg)
				}
			}
			*/
			log.Printf(
				"PID=%d UID=%d COMM=%s EXEC=%s ARGS=\"%s\"",
				e.Pid,
				e.Uid,
				cString(e.Comm[:]),
				cString(e.Filename[:]),
				"Not implemented",
				//strings.Join(args, " "),
			)
		}
	}()

	select {}
}
