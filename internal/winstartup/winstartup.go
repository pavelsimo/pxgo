package winstartup

import (
	"fmt"
	"strings"
)

type FileExistsFunc func(path string) bool

func BuildRunCommand(scriptCmd, pxini string, exists FileExistsFunc) (string, error) {
	cmd := scriptCmd
	dir, base, sep := splitExecutablePath(cmd)
	if strings.EqualFold(base, "pxgo") || strings.EqualFold(base, "pxgo.exe") {
		candidate := dir + sep + "pxgow.exe"
		if exists != nil && !exists(candidate) {
			return "", fmt.Errorf("cannot find %s", candidate)
		}
		cmd = candidate
	}
	if strings.Contains(cmd, " ") {
		cmd = `"` + cmd + `"`
	}
	if strings.Contains(pxini, " ") {
		cmd += ` "--config=` + pxini + `"`
	} else {
		cmd += ` --config=` + pxini
	}
	return cmd, nil
}

func splitExecutablePath(path string) (dir, base, sep string) {
	idx := strings.LastIndexAny(path, `\/`)
	if idx < 0 {
		return "", path, ""
	}
	return path[:idx], path[idx+1:], path[idx : idx+1]
}
