package lib

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func TryKillSlot(crypt, key string, slot int) (err error) {
	var device string
	if device, err = backingDevice(crypt); err != nil {
		return
	}

	if output, err := exec.Command(
		"cryptsetup", "luksKillSlot", device, strconv.Itoa(slot),
		"--key-file", key,
	).CombinedOutput(); err != nil {
		log.Print(string(output))
		// keep going
	}

	return nil
}

func AddKey(crypt, newKey, key string, slot int, in []byte) (err error) {
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

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Print(string(output))
		return err
	}

	return nil
}

func backingDevice(mapperDevice string) (_ string, err error) {
	var st unix.Stat_t
	if err = unix.Stat(mapperDevice, &st); err != nil {
		return "", fmt.Errorf("stat %s: %s", mapperDevice, err.Error())
	}

	backing := fmt.Sprintf("/sys/dev/block/%d:%d/slaves",
		unix.Major(st.Rdev),
		unix.Minor(st.Rdev),
	)

	var entries []os.DirEntry
	if entries, err = os.ReadDir(backing); err != nil {
		return "", fmt.Errorf("read_dir %s: %s", backing, err.Error())
	}

	if len(entries) != 1 {
		return "", fmt.Errorf("expected 1 slave device, got %d", len(entries))
	}

	return filepath.Join("/dev", entries[0].Name()), nil
}
