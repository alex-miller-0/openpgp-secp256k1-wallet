package ux

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	Pass  = "\033[32m"
	Err   = "\033[31m"
	Warn  = "\033[33m"
	Info  = "\033[34m"
	Reset = "\033[0m"
)

func PromptForSecret(prompt string, secret *string) {
	fmt.Print(prompt)
	out, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		Errorln("Error reading password")
		os.Exit(1)
	}
	*secret = string(out)
}

func Passf(format string, a ...any) {
	fmt.Printf(Pass + "[OK]  ")
	fmt.Printf(format, a...)
	fmt.Printf(Reset + "\n")
}

func Passln(s string) {
	fmt.Println(Pass + "[OK]  " + s + Reset)
}

func Errorf(format string, a ...any) {
	fmt.Printf(Err + "[ERR] ")
	fmt.Printf(format, a...)
	fmt.Printf(Reset + "\n")
}

func Errorln(s string) {
	fmt.Println(Err + "[ERR] " + s + Reset)
}

func Warnf(format string, a ...any) {
	fmt.Printf(Warn + "[WARN] ")
	fmt.Printf(format, a...)
	fmt.Printf(Reset + "\n")
}

func Warnln(s string) {
	fmt.Println(Warn + "[WARN] " + s + Reset)
}

func Infof(format string, a ...any) {
	fmt.Printf(Info + "[INFO] ")
	fmt.Printf(format, a...)
	fmt.Printf(Reset + "\n")
}

func Infoln(s string) {
	fmt.Println(Info + "[INFO] " + s + Reset)
}
