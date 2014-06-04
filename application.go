package main

import (
	"flag"
	"os"
)

func main() {
	settingsInit()
	if settings.help {
		flag.Usage()
		os.Exit(0)
	}

	input := &InputSniffPcap{}
	output := OutputHttp{}
	input.Outputs = append(input.Outputs, &output)
	input.Run("en0", "", "")
}
