// Producing a series of hashings / producing sums to check is often an IO bound process.  The logical solution is thus to read once, and perform the operations on multiple cores in parallel, allowing the work to be sharded and processed.

// This implicitly describes a single writer, multiple reader process.  Better, double-buffer: write (read from storage) to one buffer while other threads read from the other, then switch.
package multisum

//package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	// "crypto/sha3" //
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"log"
	"os"
)

// WaitGroup isn't quite what we want, the parallel processes (goroutines) need to retain their state but have completed use of the provided buffer.

type SyncUpdate uint8

const (
	Complete SyncUpdate = iota
	Error
	ReaderBuffer
	WriterBuffer
)

type SyncedByte struct {
	buffer []byte
	state  SyncUpdate
}

type SyncedWorker interface {
	// 		Receive then Send.
	Worker(<-chan SyncedByte, chan<- SyncedByte)
	//	The worker MUST implement this contract:
	//	Emit an initial return of 'WriterBuffer' to convey that it does not presently hold* (plan to use) a copy of the buffer. (This synchronizes the state machines.)
	//	Then:
	//		Recieve ReaderBuffer // A buffer to process, ReadOnly
	//		Return  WriterBuffer // Done processing
	//	  OR
	//		Recieve Complete // No further buffers
	//		Return  Complete + any result []byte (or empty)
	//	If Error is the state passed in the buffer MUST NOT be used, any prior worker state is invalid.
}

// HashWorker wraps a generic has implementation with a worker method
// :: hw := HashWorker{hash: sha1.New(), name: "sha1"}
type HashWorker struct {
	hash hash.Hash
	name string // I think if this didn't have the string I could just decorate hash.Hash with the worker method (function)...
}

func (this HashWorker) Worker(ic <-chan SyncedByte, oc chan<- SyncedByte) {
	if nil == this.hash {
		panic("HashWorker was not initiated with a valid hash, unable to continue.")
	}
	sb := SyncedByte{buffer: nil, state: WriterBuffer}
	// Declare ready for owrk
	oc <- sb
	// init hash state
	// this.Reset() // Unnecessary, this is in the constructor.  Left as a reminder.
	ll := 0

HashWorkerExit:
	for {
		sb = <-ic
		switch sb.state {
		case ReaderBuffer:
			// work
			ll += len(sb.buffer)
			this.hash.Write(sb.buffer)
			sb.state = WriterBuffer
			oc <- sb
		case Complete:
			oc <- SyncedByte{
				buffer: []byte("\n\"" + this.name + "\":\"" + hex.EncodeToString(this.hash.Sum(nil)) + "\""),
				state:  Complete}
			// Work complete, resuls delivered
			break HashWorkerExit
		default:
			// Abort, silently
			break HashWorkerExit
		}
	}
}

// HashSegsWorker is similar to HashWorker, but computes an array of hashes for each segment of rollover size
// :: hsw = HashSegsWorker{hash: sha1.New(), rollover: 4*1024*1024, name: "sha1B2"}
type HashSegsWorker struct {
	hash     hash.Hash
	rollover uint64
	name     string
}

func (this HashSegsWorker) Worker(ic <-chan SyncedByte, oc chan<- SyncedByte) {
	if nil == this.hash || 0 == len(this.name) || 0 == this.rollover {
		panic("HashSegsWorker was not initiated completely with a valid hash or name or rollover value,  unable to continue.")
	}
	sb := SyncedByte{buffer: nil, state: WriterBuffer}
	// Declare ready for owrk
	oc <- sb
	var ll, lb, lseg uint64 = 0, 0, 0
	hashSegs := map[uint64]string{}
	// this.Reset() // Unnecessary, this is in the constructor.  Left as a reminder.

HashSegsWorkerExit:
	for {
		sb = <-ic
		switch sb.state {
		case ReaderBuffer:
			// work
			lb = uint64(len(sb.buffer))
			// Note: This //completely// does not handle the case of rollover being smaller than bufsize!
			if ((ll + lb) / this.rollover) == (ll / this.rollover) {
				this.hash.Write(sb.buffer)
			} else {
				remainder := this.rollover - (ll % this.rollover)
				this.hash.Write(sb.buffer[0:remainder])
				hashSegs[lseg] = hex.EncodeToString(this.hash.Sum(nil))
				lseg++
				this.hash.Reset()
				this.hash.Write(sb.buffer[remainder:])
			}
			ll += lb
			sb.state = WriterBuffer
			oc <- sb
		case Complete:
			// prepare string for return
			hashSegs[lseg] = hex.EncodeToString(this.hash.Sum(nil))

			// Note: https://github.com/golang/go/issues/18990  There still isn't a good way of doing this:
			// My own mostly uninformed 2 cents are that somehow telling the compiler the allocated []byte will /eventually/ be frozen in to a string; otherwise anything could grab a reference to the bytes and discard or disregard any channels/syncs/guards...

			rs := make([]byte, 2+len(this.name)+2+2+(int(lseg)+1)*(this.hash.Size()*2+3))
			rsp := copy(rs, []byte("\n\""+this.name+"\":"))
			rsp += copy(rs[rsp:], []byte("[\n\""))
			rsp += copy(rs[rsp:], hashSegs[0])
			rsp += copy(rs[rsp:], []byte("\""))
			for ii := uint64(1); ii <= lseg; ii++ {
				rsp += copy(rs[rsp:], []byte(",\""))
				rsp += copy(rs[rsp:], hashSegs[ii])
				rsp += copy(rs[rsp:], []byte("\""))
			}
			_ = copy(rs[rsp:], []byte("]\n"))

			oc <- SyncedByte{
				buffer: rs, // See above note
				state:  Complete}
			// Work complete, resuls delivered
			break HashSegsWorkerExit
		default:
			// Abort, silently
			break HashSegsWorkerExit
		}
	}
}

// Returns a JSON fragment ( "ex1": [1,2,3], "ex2": "something" ... )
// It is self-generated so that worker functions may return complex nested JSON for inclusion.
// Workers MUST return either nil OR a valid 'JSON fragment' in the form of: "key":...
func ConductorReaderWorker(f io.Reader, jobs []SyncedWorker, bufsize uint64) []byte {
	b0 := make([]byte, bufsize)
	b1 := make([]byte, bufsize)
	var sbi, sbo SyncedByte // SyncedByte{buffer: nil, state: nil}

	// Setup workers
	iLen := len(jobs)
	workers := make([]chan SyncedByte, iLen)
	results := make([]chan SyncedByte, iLen)
	for ii, val := range jobs {
		csb := make(chan SyncedByte, 1)
		csr := make(chan SyncedByte)
		workers[ii] = csb
		results[ii] = csr
		go val.Worker(csb, csr)
	}

	updateWorkers := func(sbo SyncedByte) {
		for _, r := range results {
			sbi = <-r
			if sbi.state != WriterBuffer {
				panic("fileWorker: Incorrect state returned from a worker thread, corrupted output was likely.")
			}
		}
		for _, w := range workers {
			w <- sbo
		}
	}

	bufferPass := func(b []byte) bool {
		l, err := f.Read(b)

		// nil and EOF are the only error states expected
		switch err {
		case nil, io.EOF:
		default:
			panic(err)
		}

		if l > 0 {
			sbo.state = ReaderBuffer
			if int(bufsize) == l {
				sbo.buffer = b // Avoiding slicing is about 10% faster for my go test on my test system.
			} else {
				sbo.buffer = b[0:l]
			}
			updateWorkers(sbo)
		}
		if io.EOF == err {
			sbo.buffer = nil
			sbo.state = Complete
			updateWorkers(sbo)
			return false // means: trigger break
		}
		return true
	}

	for {
		if !bufferPass(b0) {
			break
		}
		if !bufferPass(b1) {
			break
		}
	}

	rets := make([]byte, 0)

	var r SyncedByte
	for ii, w := range results {
		r = <-w
		if r.state != Complete {
			panic(r.buffer)
		}
		if ii > 0 {
			rets = append(rets, []byte(",\n")...)
		}
		rets = append(rets, r.buffer...)
	}

	return rets
}

// Notes:
// Amazon S3 == 5GB (5...0? or 5 binary?) Max; MD5 integrity optional
// Backblaze B2 == 5GB (5...0 decimal) Max; SHA1 required.
// Google Cloud Platform == ?? ; Looks like MD5 as well.
func SumReader(f io.Reader, rollover uint64) []byte {
	//jobs = append(jobs, extra...)
	// I've made a /guess/ about the runtime required for each thread, and sorted them in the /HOPE/ that golang will wake the low indexed goroutines first...
	// If I blocked the writer thread, handed back a buffered channel wakeup to it, and then continued I think I could FORCE sync... but I'm not sure that would be better, and it sounds WAY more complex.
	jobs := make([]SyncedWorker, 0)
	jobs = append(jobs, HashWorker{hash: sha3.New512(), name: "sha3-512"})
	jobs = append(jobs, HashWorker{hash: sha3.New256(), name: "sha3-256"})
	jobs = append(jobs, HashWorker{hash: sha256.New(), name: "sha256"})
	jobs = append(jobs, HashSegsWorker{hash: sha1.New(), rollover: rollover, name: "sha1segs"})
	jobs = append(jobs, HashWorker{hash: sha1.New(), name: "sha1"})
	jobs = append(jobs, HashWorker{hash: md5.New(), name: "md5"})
	jobs = append(jobs, HashSegsWorker{hash: md5.New(), rollover: rollover, name: "md5segs"})
	//const bufsize = 32 * 1024

	return ConductorReaderWorker(f, jobs, 32*1024)
}

func Sum(fname string, rollover uint64) []byte {
	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
		//panic(e)
		return []byte{}
	}
	defer f.Close()

	return SumReader(f, rollover)
}
