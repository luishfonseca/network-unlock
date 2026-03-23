package lib

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func KillSlot(crypt, key string, slot int) (_ []byte, err error) {
	var device string
	if device, err = backingDevice(crypt); err != nil {
		return
	}

	return exec.Command(
		"cryptsetup", "luksKillSlot", device, strconv.Itoa(slot),
		"--key-file", key,
	).CombinedOutput()
}

func AddKey(crypt, newKey, key string, slot int, in []byte) (_ []byte, err error) {
	var device string
	if device, err = backingDevice(crypt); err != nil {
		return
	}

	cmd := exec.Command(
		"cryptsetup", "luksAddKey", device,
		"--new-keyfile", newKey,
		"--key-file", key,
		"--key-slot", strconv.Itoa(slot),
	)

	if in != nil {
		cmd.Stdin = bytes.NewReader(in)
	}

	return cmd.CombinedOutput()
}

func backingDevice(mapperDevice string) (_ string, err error) {
	var st unix.Stat_t
	if err = unix.Stat(mapperDevice, &st); err != nil {
		return
	}

	backing := fmt.Sprintf("/sys/dev/block/%d:%d/slaves",
		unix.Major(st.Rdev),
		unix.Minor(st.Rdev),
	)

	var entries []os.DirEntry
	if entries, err = os.ReadDir(backing); err != nil {
		return
	}

	if len(entries) != 1 {
		return "", fmt.Errorf("expected 1 slave device, got %d", len(entries))
	}

	return filepath.Join("/dev", entries[0].Name()), nil
}
