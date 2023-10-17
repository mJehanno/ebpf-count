package main

import (
	"fmt"
	"time"

	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	er := rlimit.RemoveMemlock()
	handleErr(fatal, "can't remove mem lock", er)

	spec, er := ebpf.LoadCollectionSpec("count.o")
	handleErr(fatal, "can't load bpf spec from module", er)

	var obj ebpfObj
	er = spec.LoadAndAssign(&obj, nil)
	handleErr(fatal, "can't load program from specs", er)

	defer func() {
		obj.Map.Close()
		obj.Prog.Close()
	}()
	_, er = link.Tracepoint("syscalls", "sys_enter_execve", obj.Prog, nil)
	handleErr(err, "can't link tracepoint", er)

	var (
		key   uint32
		count uint32
	)

	c := make(chan bool, 1)

	go func(ch chan bool) {
		for {
			time.Sleep(500 * time.Millisecond)
			n := obj.Map.Iterate()
			for n.Next(&key, &count) {
				// Order of keys is non-deterministic due to randomized map seed
				log.Infof("key: %d, value: %d\n", key, count)
			}
			if err := n.Err(); err != nil {
				log.Errorf("error in iterator, %s", err.Error())
				ch <- true
				panic(fmt.Sprint("Iterator encountered an error:", err))
			}
		}
	}(c)

	//er = obj.Map.Lookup(uint32(0), count)
	//handleErr(err, "can't lookup map", er)

	<-c

	log.Infof("count %v", count)

}

type level string

const (
	fatal level = "fatal"
	err   level = "err"
	warn  level = "warn"
)

func handleErr(lev level, msg string, er error) {
	if er != nil {
		switch lev {
		case fatal:
			log.Fatalf(msg+": %s", er)
		case err:
			log.Errorf(msg+": %s", er)
		case warn:
			log.Warnf(msg+": %s", er)
		default:
			panic("invalid log level")
		}
	}
}

type ebpfObj struct {
	Prog *ebpf.Program `ebpf:"count_syscall"`
	Map  *ebpf.Map     `ebpf:"count_map"`
}
