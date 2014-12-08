package testutil

import "os"
import "sort"
import "unicode"
import "unicode/utf8"
import "strings"
import "path/filepath"
import "io"
import "bufio"
import "testing"
import "strconv"

type TestItem struct {
	ID        string
	Names     map[string]string
	Records   string
	NumErrors int
}

func stripTag(L string) string {
	if len(L) < 3 {
		return L
	}

	r, _ := utf8.DecodeRuneInString(L)

	if unicode.IsUpper(r) {
		x := strings.IndexRune(L, ' ')
		L = L[x+1:]
	}

	return L
}

func openFileFromGOPATH(fn string) (f *os.File, err error) {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = "."
	}

	for _, p := range strings.Split(gopath, string(os.PathListSeparator)) {
		f, err = os.Open(filepath.Join(p, fn))
		if err == nil {
			return
		}
	}

	return
}

func SuiteReader(t *testing.T) <-chan TestItem {
	testItemChan := make(chan TestItem, 20)

	fpath := "src/github.com/hlandau/nctestsuite/testsuite.txt"
	f, err := openFileFromGOPATH(fpath)

	if err != nil {
		t.Fatalf("Error: Couldn't open %s: %+v", fpath, err)
	}

	go func() {
		defer f.Close()

		lineChan := make(chan string, 20)
		syncChan := make(chan struct{})

		go func() {
			reissue := false
			var L string
			var ok bool
			for {
				if reissue {
					reissue = false
				} else {
					L, ok = <-lineChan
				}

				if !ok {
					break
				}

				m := map[string]string{}

				if L != "IN" && !strings.HasPrefix(L, "IN ") {
					t.Fatalf("invalid test suite file")
				}

				id := ""
				if len(L) > 2 {
					id = L[3:]
				}

				for {
					name := <-lineChan
					value := <-lineChan
					m[name] = value

					L = <-lineChan
					if L != "IN" {
						break
					}
				}

				if !strings.HasPrefix(L, "OUT") {
					t.Fatalf("invalid test suite file")
				}

				numErrors := 0
				if len(L) > 4 {
					n, err := strconv.ParseUint(L[4:], 10, 31)
					if err != nil {
						t.Fatalf("invalid error count")
					}
					numErrors = int(n)
				}

				records := []string{}
				for {
					L, ok = <-lineChan
					if !ok || L == "IN" || strings.HasPrefix(L, "IN ") {
						reissue = true
						break
					}

					L = stripTag(L)
					records = append(records, L)
				}

				sort.Strings(records)

				// process records
				ti := TestItem{
					ID:        id,
					Names:     m,
					Records:   strings.Join(records, "\n"),
					NumErrors: numErrors,
				}

				testItemChan <- ti
			}

			close(testItemChan)
			close(syncChan)
		}()

		r := bufio.NewReader(f)
		for {
			L, err := r.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					t.Errorf("error while reading line: %+v", err)
				}
				break
			}

			L = strings.Trim(L, " \t\r\n")
			if L == "" || (len(L) > 0 && L[0] == '#') {
				continue
			}

			lineChan <- L
		}
		close(lineChan)
		<-syncChan
	}()

	return testItemChan
}
