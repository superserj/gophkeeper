// Команда gophkeeper — CLI-клиент менеджера паролей GophKeeper.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/superserj/gophkeeper/internal/client/cli"
)

// Значения подставляются при сборке через -ldflags -X.
var (
	buildVersion string
	buildDate    string
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx, buildVersion, buildDate); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
