// go:build windows

package elevated

import (
	"os"
)

func IsElevated() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		f.Close()
	}
	return err == nil
}
