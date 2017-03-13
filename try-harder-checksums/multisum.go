// Producing a series of hashings / producing sums to check is often an IO bound process.  The logical solution is thus to read once, and perform the operations on multiple cores in parallel, allowing the work to be sharded and processed.

// This implicitly describes a single writer, multiple reader process.  Better, double-buffer: write (read from storage) to one buffer while other threads read from the other, then switch.
package multisum

//package main

import (
	//"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	// "encoding/json"
	// "crypto/sha3" //
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"log"
	"os"
	//"strings"
)

// WaitGroup isn't quite what we want, the parallel processes (goroutines) need to retain their state but have completed use of the provided buffer.

// Notes:
// Amazon S3 == 5GB (5...0? or 5 binary?) Max; MD5 integrity optional
// Backblaze B2 == 5GB (5...0 decimal) Max; SHA1 required.
// Google Cloud Platform == ?? ; Looks like MD5 as well.

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

/* type SyncedString struct {
	str   string
	state SyncUpdate
} */

type SyncedWorker interface {
	worker(chan SyncedByte)
}

// HashWorker wraps a generic has implementation with a worker method
// :: hw := HashWorker{hash: sha1.New(), name: "sha1"}
type HashWorker struct {
	hash hash.Hash
	name string // I think if this didn't have the string I could just decorate hash.Hash with the worker method (function)...
}

func (this HashWorker) worker(cBuf chan SyncedByte) {
	if nil == this.hash {
		panic("HashWorker was not initiated with a valid hash, unable to continue.")
	}
	sb := SyncedByte{buffer: nil, state: WriterBuffer}
	// init hash state
	// this.Reset() // Unnecessary, this is in the constructor.  Left as a reminder.

Exit:
	for {
		cBuf <- sb
		sb = <-cBuf
		switch sb.state {
		case ReaderBuffer:
			// work
			this.hash.Write(sb.buffer)
			sb.state = WriterBuffer
			cBuf <- sb
		case Complete:
			cBuf <- SyncedByte{
				buffer: []byte("\n\"" + this.name + "\":\"" + hex.EncodeToString(this.hash.Sum(nil)) + "\""),
				state:  Complete}
			// Work complete, resuls delivered
			break Exit
		default:
			// Abort, silently
			break Exit
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

func (this HashSegsWorker) worker(cBuf chan SyncedByte) {
	if nil == this.hash || 0 == len(this.name) || 0 == this.rollover {
		panic("HashSegsWorker was not initiated completely with a valid hash or name or rollover value,  unable to continue.")
	}
	sb := SyncedByte{buffer: nil, state: WriterBuffer}
	ll, lb, lseg := uint64(0), uint64(0), uint64(0)
	hashSegs := map[uint64]string{}
	// this.Reset() // Unnecessary, this is in the constructor.  Left as a reminder.

Exit:
	for {
		cBuf <- sb
		sb = <-cBuf
		switch sb.state {
		case ReaderBuffer:
			// work
			lb = uint64(len(sb.buffer))
			// Note: This //completely// does not handle the case of rollover being smaller than bufsize!
			if ((ll + lb - 1) % this.rollover) == (ll % this.rollover) {
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
			cBuf <- sb
		case Complete:
			// prepare string for return
			hashSegs[lseg] = hex.EncodeToString(this.hash.Sum(nil))

			// Note: https://github.com/golang/go/issues/18990  There still isn't a good way of doing this:
			// My own mostly uninformed 2 cents are that somehow telling the compiler the allocated []byte will /eventually/ be frozen in to a string; otherwise anything could grab a reference to the bytes and discard or disregard any channels/syncs/guards...

			// hex is double Size(), quotes, comma (or initial :), name + 5 ( list frame [ ], returns (3))
			rs := make([]byte, len(this.name)+5+(int(lseg)+1)*(this.hash.Size()*2+3))
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

			cBuf <- SyncedByte{
				buffer: rs, // See above note
				state:  Complete}
			// Work complete, resuls delivered
			break Exit
		default:
			// Abort, silently
			break Exit
		}
	}
}

func fileErrCheck(e error) {
	if e != nil && e != io.EOF {
		panic(e)
	}
}

// Returns a JSON fragment ( "ex1": [1,2,3], "ex2": "something" ... )
// It is self-generated so that worker functions may return complex nested JSON for inclusion.
// Workers MUST return either nil OR a valid 'JSON fragment' in the form of: "key":...
func fileWorker(fname string, jobs []SyncedWorker, bufsize uint64) []byte {
	b0 := make([]byte, bufsize)
	b1 := make([]byte, bufsize)
	var sbi, sbo SyncedByte // SyncedByte{buffer: nil, state: nil}

	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
		//panic(e)
		return []byte{}
	}
	defer f.Close()

	// Setup workers
	iLen := len(jobs)
	workers := make([]chan SyncedByte, iLen)
	for ii, val := range jobs {
		spb := make(chan SyncedByte, 1)
		workers[ii] = spb
		go val.worker(spb)
	}

	updateWorkers := func(sbo SyncedByte) {
		for _, w := range workers {
			sbi = <-w
			if sbi.state != WriterBuffer {
				panic("fileWorker: Incorrect state returned from a worker thread, corrupted output was likely.")
			}
			w <- sbo
		}
	}

	for { // the entire file OR error
		l, err := f.Read(b0)
		fileErrCheck(err)
		if l > 0 {
			sbo.state = ReaderBuffer
			sbo.buffer = b0
			updateWorkers(sbo)
		}
		if io.EOF == err {
			sbo.buffer = nil
			sbo.state = Complete
			updateWorkers(sbo)
			break
		}

		l, err = f.Read(b1) // Write to the buffer in this routine, while the worker goroutines process the other buffer.
		fileErrCheck(err)

		if l > 0 {
			sbo.state = ReaderBuffer
			sbo.buffer = b1
			updateWorkers(sbo)
		}
		if io.EOF == err {
			sbo.buffer = nil
			sbo.state = Complete
			updateWorkers(sbo)
			break
		}
	}

	rets := make([]byte, 0)

	var r SyncedByte
	for ii, w := range workers {
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

func sum(fname string, rollover uint64) []byte {
	//jobs = append(jobs, extra...)
	jobs := make([]SyncedWorker, 0)
	jobs = append(jobs, HashWorker{hash: md5.New(), name: "md5"})
	jobs = append(jobs, HashWorker{hash: sha1.New(), name: "sha1"})
	jobs = append(jobs, HashWorker{hash: sha256.New(), name: "sha256"})
	jobs = append(jobs, HashWorker{hash: sha3.New256(), name: "sha3-256"})
	jobs = append(jobs, HashWorker{hash: sha3.New512(), name: "sha3-512"})
	jobs = append(jobs, HashSegsWorker{hash: md5.New(), rollover: rollover, name: "md5segs"})
	jobs = append(jobs, HashSegsWorker{hash: sha1.New(), rollover: rollover, name: "sha1segs"})
	//const bufsize = 32 * 1024
	return fileWorker(fname, jobs, 32*1024)
}
