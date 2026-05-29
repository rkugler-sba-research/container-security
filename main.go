package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func main() {
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

	fmt.Println("Tracing execve() calls... Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var e Event
		if err := binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			continue
		}

		fmt.Printf(
			"PID=%d UID=%d COMM=%s EXEC=%s\n",
			e.Pid,
			e.Uid,
			cString(e.Comm[:]),
			cString(e.Filename[:]),
		)
	}
}