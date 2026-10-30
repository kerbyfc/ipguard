//go:build !windows

package cli

// hideServiceWindow — на ОС без консолей окно автозапуска не появляется.
func hideServiceWindow() {}
