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

func TryKillSlot(crypt, key string, slot int) error {
	device, err := backingDevice(crypt)
	if err != nil {
		return err
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

func AddKey(crypt, newKey, key string, slot int, in []byte) error {
	device, err := backingDevice(crypt)
	if err != nil {
		return err
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

func backingDevice(mapperDevice string) (string, error) {
	var st unix.Stat_t
	err := unix.Stat(mapperDevice, &st)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", mapperDevice, err)
	}

	backing := fmt.Sprintf("/sys/dev/block/%d:%d/slaves",
		unix.Major(st.Rdev),
		unix.Minor(st.Rdev),
	)

	entries, err := os.ReadDir(backing)
	if err != nil {
		return "", fmt.Errorf("readdir %s: %w", backing, err)
	}

	if len(entries) != 1 {
		return "", fmt.Errorf("expected 1 slave device, got %d", len(entries))
	}

	return filepath.Join("/dev", entries[0].Name()), nil
}
