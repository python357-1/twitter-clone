package main

import (
	"context"
	"os"
)

func main() {
	component := hello()
	component.Render(context.Background(), os.Stdout)
}
