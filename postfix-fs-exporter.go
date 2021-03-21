package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "net/http"
    "math"
    "os"
    "regexp"
    "sort"
    "strings"
    "strconv"
    "syscall"
    "time"

    "github.com/prometheus/common/expfmt"
    "github.com/prometheus/common/version"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// {{{ prometheus vars
const namespace = "postfix_fs"

var (
    queue_count = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_count"),
	"How many files are in queue directory",
	[]string{"queue"}, nil,
    )
    queue_size = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_size"),
	"Total size of files in directory",
	[]string{"queue"}, nil,
    )
    queue_fssize = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_fssize"),
	"Total size of queue on filesystem",
	[]string{"queue"}, nil,
    )
    queue_age = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_age"),
	"Age (in seconds) of last file in directory",
	[]string{"queue"}, nil,
    )
    queue_error = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_error"),
	"Was there error when collecting queue",
	[]string{"queue","error"}, nil,
    )
    proc_count = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "proc_count"),
	"Count of postfix processes",
	[]string{"progname","progbin"}, nil,
    )
    proc_max = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "proc_max"),
	"Configured maximum of postfix processes",
	[]string{"progname","progbin"}, nil,
    )
)
// }}}

func OpenAt(dir *os.File, name string) (*os.File, error) { // {{{
    fdRaw, err := syscall.Openat(int(dir.Fd()), name, os.O_RDONLY, 0)
    if (err == nil) {
	return os.NewFile(uintptr(fdRaw), dir.Name() + "/" + name), nil
    } else {
	return nil, err
    }
} // }}}

type QueueDir struct { // {{{
    name string
    dir  string
}

func countDir(dir *os.File, depth int) (int, int64, int64, int64, error) {
    if depth > 20 { return 0, 0, 0, math.MaxInt64, fmt.Errorf("Too deep structure") }
    var (
	size     int64 = 0
	fssize   int64 = 0
	minTime  int64 = math.MaxInt64
	dirErr   error = nil
	firstErr error = nil
    )
    count := 0
    for dirErr == nil {
	var entries []os.FileInfo
	entries, dirErr = dir.Readdir(1024)
	if dirErr == nil {
	    for _, entry := range entries {
		var (
		    new_t int64
		    new_c int
		    new_s int64
		    new_f int64
		)
		if entry.IsDir() {
		    fd, err := OpenAt(dir, entry.Name())
		    if (err == nil) {
			new_c, new_s, new_f, new_t, err = countDir(fd, depth + 1)
			fd.Close()
			if (err != nil && firstErr == nil) { firstErr = err }
		    } else if (firstErr == nil) { firstErr = err }
		    if sys, ok := entry.Sys().(*syscall.Stat_t); ok {
			new_f += sys.Blocks * 512
		    }
		} else {
		    new_c = 1
		    new_s = entry.Size()
		    new_t = entry.ModTime().Unix()
		    if sys, ok := entry.Sys().(*syscall.Stat_t); ok {
			new_f = sys.Blocks * 512
		    } else {
			new_f = 0
		    }
		}
		count  += new_c
		size   += new_s
		fssize += new_f
		if minTime > new_t { minTime = new_t }
	    }
	}
    }

    return count, size, fssize, minTime, firstErr
}

func (qd *QueueDir) Collect(now time.Time) (int, int64, int64, int64, error) {
    dir, err := os.Open(qd.dir)
    if (err != nil) {
	return -1, 0, 0, 0, err
    }

    count, size, fssize, age, err := countDir(dir, 0)
    stat, errstat := dir.Stat()
    if errstat == nil {
	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
	    fssize += sys.Blocks * 512
	}
    }
    dir.Close()

    if count == 0 {
	age = 0
    } else {
	age = now.Unix() - age
    }
    return count, size, fssize, age, err
}
// }}}

type PostfixProc struct { // {{{
    maxValue map[string]int
    curValue map[string]int
}

var emptyLine  = regexp.MustCompile("^[[:space:]\\x00]*(?:$|#)")
var emptyStart = regexp.MustCompile("^[[:space:]\\x00]")
var wordsRe    = regexp.MustCompile("[^[:space:]\\x00]+")

func (p *PostfixProc) ParseMasterCf(mastercf string) error {
    p.maxValue = make(map[string]int)
    fd, err := os.Open(mastercf)
    if (err != nil) {
	return err
    }
    defer fd.Close()
    scanner := bufio.NewScanner(fd)
    wordpos := 0
    name  := ""
    bin   := ""
    limit := 0
    for scanner.Scan() {
	lb := scanner.Bytes()
	if emptyLine.Match(lb) { continue }
	if ! emptyStart.Match(lb) {
	    wordpos = 0
	}
	words := wordsRe.FindAll(lb, -1)
	for _, word := range words {
	    switch wordpos = wordpos + 1; wordpos {
		case 1:
		    name = string(word)
		case 7:
		    limit, err = strconv.Atoi(string(word))
		    if err != nil || limit < 0 { limit = 0 }
		case 8:
		    bin = string(word)
		    if limit > 0 {
			p.maxValue[name + " " + bin] = limit
		    }
	    }
	}
    }
    return nil
}

func (p *PostfixProc) WalkProc(procdir string, user uint32) error {
    if (user == 0) { return fmt.Errorf("Refusing to scan /proc for root processes") }
    proc, err := os.Open(procdir)
    if (err != nil) { return err }
    p.curValue = make(map[string]int)

    var dirErr error = nil
    cmdline := make([]byte,8192)

    for dirErr == nil {
	var entries []os.FileInfo
	entries, dirErr = proc.Readdir(128)
	if dirErr == nil {
	    for _, entry := range entries {
		userMatches := false
		if sys, ok := entry.Sys().(*syscall.Stat_t); ok {
		    userMatches = user == sys.Uid
		}
		if userMatches {
		    cmdfd, err := OpenAt(proc, entry.Name() + "/cmdline")
		    var cmdwords [][]byte
		    if (err == nil) {
			var n int
			n, err = cmdfd.Read(cmdline)
			if (err == nil) {
			    cmdwords = wordsRe.FindAll(cmdline[0:n], -1)
			}
			cmdfd.Close()
		    }
		    bin  := ""
		    name := ""
		    isName := false
		    for i, word := range cmdwords {
			sw := string(word)
			if i == 0 {
			    bin = sw
			} else if isName {
			    name = sw
			    isName = false
			} else if sw == "-n" {
			    isName = true
			}
		    }
		    if name == "" { name = bin }
		    if bin != "" {
			key := name + " " + bin
			p.curValue[key] += 1
		    }
		}
	    }
	}
    }
    return nil
}
// }}}

type Exporter struct { // {{{
    queueDirs  []QueueDir
    masterCf   string
    procDir    string
}

func NewExporter(spooldir string, queuenames string, master_cf string, proc_dir string) *Exporter {
    var sp string
    if (strings.HasSuffix(spooldir,"/")) {
	sp = spooldir
    } else {
	sp = spooldir + "/"
    }

    actual_dirs := wordsRe.FindAllString(queuenames,-1)

    qd := make([]QueueDir, len(actual_dirs))

    for i, name := range actual_dirs {
	qd[i].name = name
	qd[i].dir = sp + name + "/"
    }

    return &Exporter{
	queueDirs: qd,
	masterCf: master_cf,
	procDir: proc_dir,
    }
}

func (e *Exporter) getProc() (*PostfixProc, error) {
    p := &PostfixProc{}
    uid := os.Getuid()
    var uuid uint32
    if uid < 1 {
	uuid = 0
    } else {
	uuid = uint32(uid)
    }
    err := p.WalkProc(e.procDir, uuid)
    if (err != nil) { return nil, err }
    err = p.ParseMasterCf(e.masterCf)
    return p, err
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
    ch <- queue_count
    ch <- queue_size
    ch <- queue_fssize
    ch <- queue_age
    ch <- proc_count
    ch <- proc_max
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
    now := time.Now()
    for _, qd := range e.queueDirs {

	count, size, fssize, age, err := qd.Collect(now)
	var (
	    errVal int
	    errStr string
	)

	if (count >= 0) {
	    ch <- prometheus.MustNewConstMetric(
		queue_count, prometheus.GaugeValue, float64(count), qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_size, prometheus.GaugeValue, float64(size), qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_fssize, prometheus.GaugeValue, float64(fssize), qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_age, prometheus.GaugeValue, float64(age), qd.name,
	    )
	    if (err == nil) {
		errVal = 0
	    } else {
		errVal = 1
	    }
	} else {
	    errVal = 2
	}
	if (err != nil) {
	    errStr = fmt.Sprintf("%v", err)
	} else {
	    errStr = ""
	}
	ch <- prometheus.MustNewConstMetric(
	    queue_error, prometheus.GaugeValue, float64(errVal), qd.name, errStr,
	)
    }
    p, _ := e.getProc()
    if p != nil {
	keySet := make(map[string]bool)
	for k := range p.curValue { keySet[k] = true }
	for k := range p.maxValue { keySet[k] = true }
	keys := make([]string, len(keySet))
	i:= 0
	for k := range keySet {
	    keys[i] = k
	    i++
	}
	sort.Strings(keys)
	for _, k := range keys {
	    kk := strings.SplitN(k, " ", 2)
	    if len (kk) < 2 { continue }
	    ch <- prometheus.MustNewConstMetric(
		proc_count, prometheus.GaugeValue, float64(p.curValue[k]), kk[0], kk[1],
	    )
	    max := p.maxValue[k]
	    if (max > 0) {
		ch <- prometheus.MustNewConstMetric(
		    proc_max, prometheus.GaugeValue, float64(max), kk[0], kk[1],
		)
	    }
	}
    }
}

var (
    // Replace various quotes and backslashes in original text
    // with '~' sign,
    // influxdb is not consistent with itself when parsing quotes
    // and when parsing consecutive backslashes.
    dangerousChars = regexp.MustCompile("[\\\"'`]")
    // Escape comma and equal sign
    escapeChars    = regexp.MustCompile("([,=])")
    // Replace control characters and space by escaped space
    whiteChars     = regexp.MustCompile("[[:cntrl:][:space:]]")
)

func (e *Exporter) Influxdb(writer io.Writer) {
    now := time.Now()
    nowi := now.UnixNano()

    for _, qd := range e.queueDirs {
	count, size, fssize, age, err := qd.Collect(now)
	var errStr string = ""
	if (err != nil) {
	    errStr = fmt.Sprintf("%v", err)
	    errStr = dangerousChars.ReplaceAllString(errStr, "~")
	    errStr = whiteChars.ReplaceAllString(errStr, "\\ ")
	    errStr = escapeChars.ReplaceAllString(errStr, "\\$1")
	} else {
	    errStr = "none"
	}
	agei := int64(age)
	if (count >=0 ) {
	    errval := 0
	    if (err != nil) { errval = 1 }
	    fmt.Fprintf(writer, "%v_queue,queue=%v,error=%v count=%di,size=%di,fssize=%di,age=%di,errval=%di %v\n",
	                namespace, qd.name, errStr, count, size, fssize, agei, errval, nowi)
	} else {
	    fmt.Fprintf(writer, "%v_queue,queue=%v,error=%v errval=2i %v\n", namespace, qd.name, errStr, nowi)
	}
    }

    p, _ := e.getProc()
    if p != nil {
	keySet := make(map[string]bool)
	for k := range p.curValue { keySet[k] = true }
	for k := range p.maxValue { keySet[k] = true }
	keys := make([]string, len(keySet))
	i:= 0
	for k := range keySet {
	    keys[i] = k
	    i++
	}
	sort.Strings(keys)
	for _, k := range keys {
	    keyStr := dangerousChars.ReplaceAllString(k, "~")
	    keyStr = escapeChars.ReplaceAllString(keyStr, "\\$1")
	    keyStr = "progname=" + strings.Replace(keyStr, " ", ",progbin=", 1)
	    keyStr = whiteChars.ReplaceAllString(keyStr, "\\ ")
	    max := p.maxValue[k]
	    if (max > 0) {
		fmt.Fprintf(writer, "%v_proc,%v count=%di,max=%di %v\n",
		            namespace, keyStr, p.curValue[k], max, nowi)
	    } else {
		fmt.Fprintf(writer, "%v_proc,%v count=%di %v\n",
		            namespace, keyStr, p.curValue[k], nowi)
	    }
	}
    }
}

func (e *Exporter) InfluxHandler() (func(http.ResponseWriter, *http.Request)) {
    return func(w http.ResponseWriter, _ *http.Request) {
	e.Influxdb(w)
    }
}
// }}}

var (
    test     = flag.Bool("test", false, "test run - gather methrics and print them")
    influx   = flag.Bool("test-influx", false, "single run - gather methrics and print them in influx line format")
    addr     = flag.String("web.listen-address", "127.0.0.1:9991", "The address to listen on for HTTP requests.")

    spoolDir  = flag.String("spooldir", "/var/spool/postfix/", "Postfix directory with queue directories")
    queueDirs = flag.String("queuedirs", "incoming active deferred bounce corrupt", "Space separated names of queues")
    procDir   = flag.String("proc", "/proc", "procfs mount directory")
    masterCf  = flag.String("mastercf", "/etc/postfix/master.cf", "Postfix master.cf, to parse maximum number of processes")
)

func main() { // {{{
    //var err error

    flag.Parse()

    exporter := NewExporter(*spoolDir, *queueDirs, *masterCf, *procDir)
    if *influx {
	exporter.Influxdb(os.Stdout);
	os.Exit(0);
	return
    }

    prometheus.MustRegister(exporter)
    prometheus.MustRegister(version.NewCollector(namespace))

    if *test {
	// Run full prometheus gather and print to stdout
	gth := prometheus.DefaultGatherer
	mfs, err := gth.Gather()
	enc := expfmt.NewEncoder(os.Stdout, expfmt.FmtText)
	if err != nil {
	    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	for _, mf := range mfs {
	    err = enc.Encode(mf)
	    if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	    }
	}
	return
    } else {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/influx", exporter.InfluxHandler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	    w.Write([]byte(`<html>
  <head><title>Postfix FS Exporter</title></head>
  <body><h1>Postfix FS Exporter</h1>
  <p><a href="/metrics">Metrics</a></p>
  <p><a href="/influx">Metrics in influxdb format</a></p>
</html>
`))
	})
	err := http.ListenAndServe(*addr, nil)
	if (err != nil) {
	    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	    os.Exit(1)
	}
    }
} // }}}
