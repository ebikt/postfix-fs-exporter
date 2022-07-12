package main

import (
    "bufio"
    "bytes"
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
    "os/user"

    "golang.org/x/sys/unix"

    "github.com/prometheus/common/expfmt"
    "github.com/prometheus/common/version"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/yookoala/realpath"
)

// {{{ prometheus vars
const namespace = "postfix_fs"

var (
    queue_count = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_count"),
	"How many files are in queue directory",
	[]string{"instance", "queue"}, nil,
    )
    queue_size = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_size"),
	"Total size of files in directory",
	[]string{"instance", "queue"}, nil,
    )
    queue_fssize = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_fssize"),
	"Total size of queue on filesystem",
	[]string{"instance", "queue"}, nil,
    )
    queue_age = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_age"),
	"Age (in seconds) of last file in directory",
	[]string{"instance", "queue"}, nil,
    )
    queue_error = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "queue_error"),
	"Was there error when collecting queue",
	[]string{"instance", "queue", "error"}, nil,
    )
    proc_count = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "proc_count"),
	"Count of postfix processes",
	[]string{"instance", "progname", "progbin"}, nil,
    )
    proc_max = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "proc_max"),
	"Configured maximum of postfix processes",
	[]string{"instance", "progname", "progbin"}, nil,
    )
)
// }}}

var (
    debug = false
)

func OpenAt(dir *os.File, name string) (*os.File, error) { // {{{
    fdRaw, err := syscall.Openat(int(dir.Fd()), name, os.O_RDONLY, 0)
    if (err == nil) {
	return os.NewFile(uintptr(fdRaw), dir.Name() + "/" + name), nil
    } else {
	return nil, err
    }
} // }}}

func ReadlinkAt(dir *os.File, path string) (string, error) { // {{{
	// Allocate the buffer exponentially like os.Readlink does.
	for bufsz := 128; ; bufsz *= 2 {
		buf := make([]byte, bufsz)
		n, err := unix.Readlinkat(int(dir.Fd()), path, buf)
		if err != nil {
			return "", err
		}
		if n < bufsz {
			return string(buf[0:n]), nil
		}
	}
} // }}}

type QueueDir struct { // {{{
    name     string
    instance string
    dir      string
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
    instanceDirs map[string]string
    maxValue map[string]map[string]int
    curValue map[string]map[string]int
    sortedInstances []string
}

var emptyLine  = regexp.MustCompile("^[[:space:]\\x00]*(?:$|#)")
var emptyStart = regexp.MustCompile("^[[:space:]\\x00]")
var wordsRe    = regexp.MustCompile("[^[:space:]\\x00]+")

func (p *PostfixProc) ParseMasterCf(instance string, masterCf string) error {
    maxValue := make(map[string]int)
    curValue := make(map[string]int)
    fd, err := os.Open(masterCf)
    if (err != nil) {
	return nil
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
			maxValue[name + " " + bin] = limit
			curValue[name + " " + bin] = 0
		    }
	    }
	}
    }
    p.maxValue[instance] = maxValue
    p.curValue[instance] = curValue
    return nil
}

func (p *PostfixProc) WalkProc(procDir string, user int) error {
    check_user := user >= 0
    uid := uint32(user)
    if (user == 0) { return fmt.Errorf("Refusing to scan /proc for root processes") }
    proc, err := os.Open(procDir)
    if (err != nil) { return err }

    var dirErr error = nil
    cmdline := make([]byte,8192)

    if (debug) {
	fmt.Fprintf(os.Stderr, "Instances %v\n", len(p.instanceDirs))
	for instX, dirX := range(p.instanceDirs) {
	    fmt.Fprintf(os.Stderr, "Instance |%v| -> dir |%v|\n", instX, dirX)
	}
    }

    for dirErr == nil {
	var entries []os.FileInfo
	entries, dirErr = proc.Readdir(128)
	if dirErr == nil {
	    for _, entry := range entries {
		userMatches := !check_user
		if (check_user) {
		    if sys, ok := entry.Sys().(*syscall.Stat_t); ok {
			userMatches = uid == sys.Uid
		    }
		}
		if userMatches {
		    dir, err := ReadlinkAt(proc, entry.Name() + "/cwd")
		    if (debug) {
			fmt.Fprintf(os.Stderr, "Process %v, currdir %v, error %v, instnce %v\n", entry.Name(), dir, err, p.instanceDirs[dir])
		    }
		    if (err != nil) { continue; }
		    instance := p.instanceDirs[dir]
		    if (instance == "") { continue; }

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
		    if bin != "" && err == nil {
			key := name + " " + bin
			p.curValue[instance][key] += 1
		    }
		}
	    }
	}
    }
    return nil
}

// }}}

type Exporter struct { // {{{
    directories []string
    masterCf   string
    multiCf    string
    procDir    string
    spoolDir   string
    uid        int
}

func NewExporter(spooldir string, queuenames string, master_cf string, multi_cf string, proc_dir string, uid int) *Exporter {
    var sp string
    if (strings.HasSuffix(spooldir,"/")) {
	sp = spooldir
    } else {
	sp = spooldir + "/"
    }

    directories := wordsRe.FindAllString(queuenames,-1)

    return &Exporter{
	directories: directories,
	masterCf: master_cf,
	multiCf: multi_cf,
	procDir: proc_dir,
	spoolDir: sp,
	uid: uid,
    }
}

var keyRe = regexp.MustCompile("^[[:space:]]*([[:word:]]+)[[:space:]]*=[[:space:]]*")
func parseMain(fileName string) (map[string]string, error) {
    fd, err := os.Open(fileName)
    if (err != nil) {
	return nil, err
    }
    defer fd.Close()
    scanner := bufio.NewScanner(fd)
    ret := make(map[string]string)
    for scanner.Scan() {
	lb := scanner.Bytes()
	keyA := keyRe.FindSubmatch(lb)
	if (keyA == nil) { continue }
	ret[ string(bytes.ToLower(keyA[1])) ] = string(bytes.TrimSpace(lb[ len(keyA[0]) : ] ))
    }
    return ret, nil
}

func TryReal(fpath string) (string) {
    rpath, err := realpath.Realpath(fpath)
    if err == nil { return rpath }
    return fpath
}

func (e *Exporter) RealSpool(mainCf map[string]string, err error) (string) {
    var fpath string
    if err != nil {
	fpath = ""
    } else {
	fpath = mainCf["queue_directory"]
    }
    if (fpath == "") {
	fpath = e.spoolDir
    }
    return TryReal(fpath)
}

var postfixDirsRe = regexp.MustCompile("[^\x00, \t\r\n]+")



func (e *Exporter) parseMulti() ([]QueueDir, *PostfixProc, error) {
    multiCf, err := parseMain(e.multiCf)
    if (err != nil) {
	multiCf = make(map[string]string)
    }
    var cfDirs []string
    if (strings.ToLower(multiCf["multi_instance_enable"]) == "yes") {
	cfDirs = postfixDirsRe.FindAllString(multiCf["multi_instance_directories"], -1)
    }
    var masterCfs = make(map[string]string)
    var queueDirs = make(map[string]string)
    var dir2instance = make(map[string]string)
    if (cfDirs == nil || len(cfDirs) == 0) {
	masterCfs["(single)"] = e.masterCf
	d := e.RealSpool(multiCf, nil)
	queueDirs["(single)"] = d
	dir2instance[d] = "(single)"
    } else {
	for _, dir := range(cfDirs) {
	    masterCfs[dir] = dir + "/master.cf"
	    d := e.RealSpool(parseMain(dir + "/main.cf"))
	    queueDirs[dir] = d
	    dir2instance[d] = dir
	}
    }
    i := 0
    p := &PostfixProc{}
    p.instanceDirs = dir2instance
    p.sortedInstances = make([]string, len(queueDirs))
    p.maxValue = make(map[string]map[string]int)
    p.curValue = make(map[string]map[string]int)
    for instance := range(queueDirs) {
      p.sortedInstances[i] = instance
      i += 1
    }
    sort.Strings(p.sortedInstances)
    i = 0
    qd := make([]QueueDir, len(queueDirs) * len(e.directories))
    for _, instance := range(p.sortedInstances) {
	spoolDir := queueDirs[instance]
	var sp string
	if (strings.HasSuffix(spoolDir,"/")) {
	   sp = spoolDir
	} else {
	   sp = spoolDir + "/"
	}

	for _, dir := range(e.directories) {
	    qd[i].instance = instance
	    qd[i].name = dir
	    qd[i].dir = sp + dir + "/"
	    i += 1
	}
    }

    for instance, masterCf := range(masterCfs) {
	p.ParseMasterCf(instance, masterCf) // ignore error
    }
    return qd, p, nil
}

func (e *Exporter) WalkProc(p *PostfixProc) error {
    return p.WalkProc(e.procDir, e.uid)
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
    queues, p, err := e.parseMulti();
    if (err != nil) { return; }
    for _, qd := range queues {

	count, size, fssize, age, err := qd.Collect(now)
	var (
	    errVal int
	    errStr string
	)

	if (count >= 0) {
	    ch <- prometheus.MustNewConstMetric(
		queue_count, prometheus.GaugeValue, float64(count), qd.instance, qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_size, prometheus.GaugeValue, float64(size), qd.instance, qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_fssize, prometheus.GaugeValue, float64(fssize), qd.instance, qd.name,
	    )
	    ch <- prometheus.MustNewConstMetric(
		queue_age, prometheus.GaugeValue, float64(age), qd.instance, qd.name,
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
	    queue_error, prometheus.GaugeValue, float64(errVal), qd.instance, qd.name, errStr,
	)
    }
    if p != nil {
	e.WalkProc(p)
	for _, instance:= range p.sortedInstances {
	    curValue := p.curValue[instance]
	    maxValue := p.maxValue[instance]
	    keys := make([]string, len(curValue))
	    i := 0
	    for k := range curValue {
	      keys[i] = k
	      i++
	    }
	    sort.Strings(keys)
	    for _, k := range keys {
		kk := strings.SplitN(k, " ", 2)
		if len (kk) < 2 { continue }
		ch <- prometheus.MustNewConstMetric(
		    proc_count, prometheus.GaugeValue, float64(curValue[k]), instance, kk[0], kk[1],
		)
		max := maxValue[k]
		if (max > 0) {
		    ch <- prometheus.MustNewConstMetric(
			proc_max, prometheus.GaugeValue, float64(max), instance, kk[0], kk[1],
		    )
		}
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

    queues, p, err := e.parseMulti()
    if (err != nil) { return; }

    for _, qd := range queues {
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
	    fmt.Fprintf(writer, "%v_queue,instance=%v,queue=%v,error=%v count=%di,size=%di,fssize=%di,age=%di,errval=%di %v\n",
	                namespace, qd.instance, qd.name, errStr, count, size, fssize, agei, errval, nowi)
	} else {
	    fmt.Fprintf(writer, "%v_queue,instance=%v,queue=%v,error=%v errval=2i %v\n", namespace, qd.instance, qd.name, errStr, nowi)
	}
    }

    if p != nil {
	e.WalkProc(p)
	for _, instance := range p.sortedInstances {
	    instanceStr := dangerousChars.ReplaceAllString(instance, "~")
	    instanceStr = escapeChars.ReplaceAllString(instanceStr, "\\$1")
	    instanceStr = whiteChars.ReplaceAllString(instanceStr, "\\ ")
	    curValue := p.curValue[instance]
	    maxValue := p.maxValue[instance]
	    keys := make([]string, len(curValue))
	    i := 0
	    for k := range curValue {
	      keys[i] = k
	      i++
	    }
	    sort.Strings(keys)
	    sort.Strings(keys)
	    for _, k := range keys {
		keyStr := dangerousChars.ReplaceAllString(k, "~")
		keyStr = escapeChars.ReplaceAllString(keyStr, "\\$1")
		keyStr = "progname=" + strings.Replace(keyStr, " ", ",progbin=", 1)
		keyStr = whiteChars.ReplaceAllString(keyStr, "\\ ")
		max := maxValue[k]
		if (max > 0) {
		    fmt.Fprintf(writer, "%v_proc,instance=%v,%v count=%di,max=%di %v\n",
				namespace, instanceStr, keyStr, curValue[k], max, nowi)
		} else {
		    fmt.Fprintf(writer, "%v_proc,instance=%v,%v count=%di %v\n",
				namespace, instanceStr, keyStr, curValue[k], nowi)
		}
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
    procDir   = flag.String("proc", "/proc", "procfs mount directory, needs to run as root, to see working directories of processes")
    masterCf  = flag.String("mastercf", "/etc/postfix/master.cf", "Postfix master.cf, to parse maximum number of processes")
    multiCf   = flag.String("multicf", "/etc/postfix/main.cf", "Postfix main.cf, to parse for postfix multi_instance_enable");
    userName  = flag.String("user", "postfix", "Scan processes belonging to this username (only if launched as root)")
)

func main() { // {{{
    //var err error

    flag.Parse()

    uid := os.Getuid()
    if (uid == 0) {
	if (*userName == "-") {
	    uid = -1
	} else {
	    u, err := user.Lookup(*userName)
	    if (err != nil) {
		fmt.Fprintf(os.Stderr, "Cannot find user " + *userName + ": " + err.Error())
		os.Exit(1)
	    }
	    uid, err = strconv.Atoi(u.Uid)
	    if (err != nil) {
		fmt.Fprintf(os.Stderr, "Error converting userid of " + *userName + ": " + err.Error())
		os.Exit(1)
	    }
	}
    }

    exporter := NewExporter(*spoolDir, *queueDirs, *masterCf, *multiCf, *procDir, uid)
    if *influx {
	debug = true
	exporter.Influxdb(os.Stdout);
	os.Exit(0);
	return
    }

    prometheus.MustRegister(exporter)
    prometheus.MustRegister(version.NewCollector(namespace))

    if *test {
	debug = true
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
