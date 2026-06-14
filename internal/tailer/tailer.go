package tailer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type LogLine struct {
	FilePath string
	Line     string
	Offset   int64
	Time     time.Time
}

type FileTracker struct {
	Path    string
	Inode   uint64
	Size    int64
	Offset  int64
	File    *os.File
	Reader  *bufio.Reader
	IsNew   bool
}

type Tailer struct {
	logDir       string
	logPatterns  []string
	trackers     map[string]*FileTracker
	mu           sync.Mutex
	lineChan     chan LogLine
	done         chan struct{}
	pollInterval time.Duration
	follow       bool
}

func New(logDir string, logPatterns []string, pollInterval time.Duration, follow bool) *Tailer {
	return &Tailer{
		logDir:       logDir,
		logPatterns:  logPatterns,
		trackers:     make(map[string]*FileTracker),
		lineChan:     make(chan LogLine, 1024),
		done:         make(chan struct{}),
		pollInterval: pollInterval,
		follow:       follow,
	}
}

func (t *Tailer) LineChan() <-chan LogLine {
	return t.lineChan
}

func (t *Tailer) Stop() {
	close(t.done)
}

func (t *Tailer) Start() error {
	if err := t.scanFiles(); err != nil {
		return err
	}

	go t.pollLoop()
	return nil
}

func (t *Tailer) scanFiles() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, pattern := range t.logPatterns {
		matches, err := filepath.Glob(filepath.Join(t.logDir, pattern))
		if err != nil {
			return fmt.Errorf("glob pattern %q failed: %w", pattern, err)
		}

		for _, filePath := range matches {
			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			if info.IsDir() {
				continue
			}

			inode := getInode(info)
			tracker, exists := t.trackers[filePath]

			if !exists {
				offset := int64(0)
				if t.follow {
					offset = info.Size()
				}
				if err := t.openFile(filePath, inode, offset); err != nil {
					return err
				}
				t.trackers[filePath].IsNew = true
			} else if tracker.Inode != inode {
				t.closeFile(filePath)
				if err := t.openFile(filePath, inode, 0); err != nil {
					return err
				}
				t.trackers[filePath].IsNew = true
			}
		}
	}

	return nil
}

func (t *Tailer) openFile(filePath string, inode uint64, offset int64) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}

	if offset > 0 {
		if _, err := file.Seek(offset, 0); err != nil {
			file.Close()
			return fmt.Errorf("failed to seek %s: %w", filePath, err)
		}
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	t.trackers[filePath] = &FileTracker{
		Path:   filePath,
		Inode:  inode,
		Size:   info.Size(),
		Offset: offset,
		File:   file,
		Reader: bufio.NewReader(file),
	}

	return nil
}

func (t *Tailer) closeFile(filePath string) {
	if tracker, ok := t.trackers[filePath]; ok {
		if tracker.File != nil {
			tracker.File.Close()
		}
		delete(t.trackers, filePath)
	}
}

func (t *Tailer) pollLoop() {
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()
	defer close(t.lineChan)

	idleCount := 0
	maxIdle := 3

	for {
		select {
		case <-t.done:
			t.mu.Lock()
			for path := range t.trackers {
				t.closeFile(path)
			}
			t.mu.Unlock()
			return
		case <-ticker.C:
			if err := t.scanFiles(); err != nil {
				continue
			}
			linesRead := t.readAll()
			if linesRead == 0 {
				idleCount++
			} else {
				idleCount = 0
			}

			if !t.follow && idleCount >= maxIdle {
				t.mu.Lock()
				for path := range t.trackers {
					t.closeFile(path)
				}
				t.mu.Unlock()
				return
			}
		}
	}
}

func (t *Tailer) readAll() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	totalLines := 0

	for path, tracker := range t.trackers {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		currentSize := info.Size()
		if currentSize < tracker.Size {
			tracker.Offset = 0
			if _, err := tracker.File.Seek(0, 0); err != nil {
				continue
			}
			tracker.Reader = bufio.NewReader(tracker.File)
		}
		tracker.Size = currentSize

		for {
			line, err := tracker.Reader.ReadString('\n')
			if len(line) > 0 {
				tracker.Offset += int64(len(line))
				trimmed := line
				if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\n' {
					trimmed = trimmed[:len(trimmed)-1]
				}
				if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\r' {
					trimmed = trimmed[:len(trimmed)-1]
				}

				if len(trimmed) > 0 {
					t.lineChan <- LogLine{
						FilePath: path,
						Line:     trimmed,
						Offset:   tracker.Offset,
						Time:     time.Now(),
					}
					totalLines++
				}
			}
			if err != nil {
				break
			}
		}
	}

	return totalLines
}

func getInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
