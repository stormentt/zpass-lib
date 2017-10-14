package util

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
)

//AskPass prints the prompt to the screen & then reads input
func AskPass(prompt string) (string, error) {
	fmt.Print(prompt)
	input, err := terminal.ReadPassword(0)
	if err != nil {
		return "", err
	}
	fmt.Println("")
	return string(input), nil
}
