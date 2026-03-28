package file

import "os"

func Exist(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}

func Remove(filename string) error {
	if err := os.Remove(filename); err != nil {
		return err
	}
	return nil
}
