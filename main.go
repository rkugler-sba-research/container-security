package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strings"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	MaxArgs = 20
	ArgSize = 128
)

const daemonEnv = "GO_DAEMONIZED"

type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [ArgSize]byte
	Argc     int32
	Argv     [MaxArgs][ArgSize]byte
}

func cString(buf []byte) string {
	n := bytes.IndexByte(buf, 0)
	if n == -1 {
		n = len(buf)
	}
	return string(buf[:n])
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
 
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.TraceExecve,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig,
		os.Interrupt,
		syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("ringbuf read error: %v", err)
				break
			}

			var event Event

			if err := binary.Read(
				bytes.NewBuffer(record.RawSample),
				binary.LittleEndian,
				&event,
			); err != nil {
				continue
			}

			args := make([]string, 0, event.Argc)

			for i := 0; i < int(event.Argc); i++ {
				arg := cString(event.Argv[i][:])
				if arg != "" {
					args = append(args, arg)
				}
			}

			log.Printf(
				"PID=%d UID=%d COMM=%s FILE=%s ARGS='%s'",
				event.Pid,
				event.Uid,
				cString(event.Comm[:]),
				cString(event.Filename[:]),
				strings.Join(args, " "),
			)
		}
	}()

	select {}
}
