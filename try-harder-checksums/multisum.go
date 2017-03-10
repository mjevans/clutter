// Producing a series of hashings / producing sums to check is often an IO bound process.  The logical solution is thus to read once, and perform the operations on multiple cores in parallel, allowing the work to be sharded and processed.

// This implicitly describes a single writer, multiple reader process.  Better, double-buffer: write (read from storage) to one buffer while other threads read from the other, then switch.
package multisum

//package main

import (
"io"
"log"
"os"
"strings"
"bytes"
"encoding/json"
)

// WaitGroup isn't quite what we want, the parallel processes (goroutines) need to retain their state but have completed use of the provided buffer.

type SyncUpdate uint8

const (
	Complete SyncUpdate = iota
	Error
	ReaderBuffer
	WriterBuffer
)

type SyncedPByte struct {
	buffer *[]byte
	state SyncUpdate
}

type SyncedByte struct {
	buffer []byte
	state SyncUpdate
}

type SyncedWorker interface {
	worker(chan SyncedPByte, chan SyncedByte)
}



func (this baseHashObjectType) worker(cBuf chan SyncedPByte, cRet chan SyncedByte) {
	sb := SyncedPByte{buffer:nil, state: WriterBuffer}
	var b []byte

Exit:
	for {
		cBuf <- sb
		sb <- cBuf
		switch sb.state {
			case ReaderBuffer:
				&b = sb.buffer
				// work
				sb.state = WriterBuffer
				cBuf <- sb
			case Complete:
				sb.state = WriterBuffer
				cBuf <- sb
				// prepare []byte for return
				cRet <- SyncedByte{buffer: _, state: Complete}
				// Work complete, resuls delivered
				break Exit
			case true:
				// Abort, silently
				break Exit
		}
	}
}



func fileErrCheck(e error){
	if e != nil && e != io.EOF {
		panic(e)
	}
}

// Returns a JSON structure.
// It is self-generated so that worker functions may return complex nested JSON for inclusion.
// Workers MUST return either nil OR a valid 'JSON fragment' in the form of: "key"=...
func fileWorker(fname string, jobs []SyncedWorker) []byte {
	bufsize := 1024 * 1024 / 8
	b0 := make([]byte, bufsize)
	b1 := make([]byte, bufsize)
	var sbi SyncedPByte // SyncedPByte{buffer: nil, state: nil}
	var sbo SyncedPByte

	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
		//panic(e)
		return
	}
	defer f.Close()

	// Setup workers
	iLen := len(jobs)
	workers := make([]chan SyncedPByte,	iLen) // I'm still not sure I should be using a slice here instead of an array: This is a local scope, a fixed known size, is the slice simply better as a default?
	results := make([]chan SyncedByte,	iLen)
	for ii := 0; ii < iLen; ii++ {
		spb = make(chan SyncedPByte, 1)
		sbr  = make(chan SyncedByte)
		workers[ii] = spb
		results[ii] = sbr
		go jobs[ii].worker(spb, sbr)
	}
	
	func updateWorkers(sbo SyncedPByte) {
		for ii := 0; ii < iLen; ii++ {
			sbi <- workers[ii]
			if sbi.state != WriterBuffer {
				panic("fileWorker: Incorrect state returned from a worker thread, corrupted output was likely.")
			}
			workers[ii] <- sbo
		}
	}
	
	for { // the entire file OR error
		l, err := f.Read(&b0)
		fileErrCheck(err)
		if l > 0 {
			sbo.state = ReaderBuffer
			sbo.buffer = &b0
			updateWorkers(sbo)
		}
		if io.EOF == err {
			sbo.buffer = nil
			sbo.state = Complete
			updateWorkers(sbo)
			break;
		}

		l, err := f.Read(&b1) // Write to the buffer in this routine, while the worker goroutines process the other buffer.
		fileErrCheck(err)
		
		if l > 0 {
			sbo.state = ReaderBuffer
			sbo.buffer = &b1
			updateWorkers(sbo)
		}
		if io.EOF == err {
			sbo.buffer = nil
			sbo.state = Complete
			updateWorkers(sbo)
			break;
		}
	}
	
	var rets := make([][]byte)
	var r SyncedByte
	for ii := 0; ii < iLen; ii++ {
		r <- results[ii]
		if r.state != Complete {
			panic(r.buffer)
		}
		rets.append(r.buffer)
	}

	return bytes.Join(rets, ", ".([]byte))
}

func sum(fname string) []byte {
	//jobs = append(jobs, extra...)
}

func main() {
}

