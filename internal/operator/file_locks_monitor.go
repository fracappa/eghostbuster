package operator

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/fracappa/eghostbuster/pkg/bpf"
	"github.com/fracappa/eghostbuster/pkg/file"
)

type ExitEvent struct {
	PID      uint32
	Filename string
}

func StartFileLocksMonitor(ctx context.Context, objs *bpf.EGhostBusterObjects) error {
	log.Printf("File Locks monitor started")
	rd, err := ringbuf.NewReader(objs.ExitEvents)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Close reader when context is cancelled
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		exitEvent := ExitEvent{
			PID:      binary.LittleEndian.Uint32(record.RawSample[0:4]),
			Filename: string(record.RawSample[4 : 4+bytes.IndexByte(record.RawSample[4:], 0)]),
		}

		// Parse the connection_info struct from BPF
		log.Printf("Process exited: PID=%d, File=%s", exitEvent.PID, exitEvent.Filename)

		if !file.Exist(exitEvent.Filename) {
			continue
			// log.Printf("file %s not found", exitEvent.Filename)
		} else {
			if err := file.Remove(exitEvent.Filename); err != nil {
				log.Printf("error while removing file: %s (err: %v)", exitEvent.Filename, err)
			}
			log.Printf("lock file: %s successfully deleted", exitEvent.Filename)
		}
	}
}
