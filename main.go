package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}

const envDaemon = "GO_DAEMONIZED"

func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func forkDaemon() error {
	if os.Getenv(envDaemon) == "1" {
		return nil
	}
	// re-exec same binary
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), envDaemon+"=1")
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
	log.Printf("forked daemon pid=%d\n", cmd.Process.Pid)

	os.Exit(0) // parent exits immediately
	return nil
}

func main() {
	if err := forkDaemon(); err != nil {
		log.Fatal(err)
	}

	logFile, err := os.OpenFile(
		"/tmp/exec.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	fmt.Printf("daemon running pid=%d ppid=%d\n", os.Getpid(), os.Getppid())

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
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
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("tracing execve events...")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Println("ringbuf error:", err)
				return
			}

			var e Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}

			log.Printf(
				"PID=%d UID=%d COMM=%s EXEC=%s",
				e.Pid,
				e.Uid,
				cString(e.Comm[:]),
				cString(e.Filename[:]),
			)
		}
	}()

	select {}
}