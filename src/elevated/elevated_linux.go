// go:build linux

package elevated

import "os"

func IsElevated() bool {
	return os.Getuid() == 0
}
