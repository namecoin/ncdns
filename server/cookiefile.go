package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

func readCookieFile(path string) (username, password string, err error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	s := strings.TrimSpace(string(b))
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("malformed cookie file")
		return
	}

	username, password = parts[0], parts[1]
	return
}

func cookieRetriever(path string) func() (username, password string, err error) {
	lastCheckTime := time.Time{}
	lastModTime := time.Time{}

	curUsername, curPassword := "", ""
	var curError error

	doUpdate := func() {
		if !lastCheckTime.IsZero() && time.Now().Before(lastCheckTime.Add(30*time.Second)) {
			return
		}

		lastCheckTime = time.Now()

		st, err := os.Stat(path)
		if err != nil {
			curError = err
			return
		}

		modTime := st.ModTime()
		if !modTime.Equal(lastModTime) {
			lastModTime = modTime
			curUsername, curPassword, curError = readCookieFile(path)
		}
	}

	return func() (username, password string, err error) {
		doUpdate()
		return curUsername, curPassword, curError
	}
}
