// Package cli описывает команды клиента GophKeeper.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/superserj/gophkeeper/internal/client/app"
	"github.com/superserj/gophkeeper/internal/client/localstore"
	"github.com/superserj/gophkeeper/internal/client/remote"
	"github.com/superserj/gophkeeper/internal/model"
)

// Значения по умолчанию.
const (
	defaultAddress = "127.0.0.1:3200"
	storeDirName   = ".gophkeeper"
	storeFileName  = "vault.db"
)

// masterPasswordEnv позволяет передать мастер-пароль скриптам и тестам,
// когда команду запускают без терминала.
const masterPasswordEnv = "GOPHKEEPER_MASTER_PASSWORD"

// options — общие флаги всех команд.
type options struct {
	address   string
	caCert    string
	storePath string
}

// Execute выполняет команду, разобрав аргументы командной строки.
func Execute(ctx context.Context, buildVersion, buildDate string) error {
	return Run(ctx, os.Args[1:], os.Stdout, buildVersion, buildDate)
}

// Run выполняет команду с заданными аргументами и выводом. Отдельная функция
// нужна тестам: они гоняют команды без подмены глобального состояния процесса.
func Run(ctx context.Context, args []string, out io.Writer, buildVersion, buildDate string) error {
	opts := &options{}

	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper stores private data on a remote server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&opts.address, "address", "a", defaultAddress, "server address")
	root.PersistentFlags().StringVar(&opts.caCert, "cacert", "", "path to the server CA certificate")
	root.PersistentFlags().StringVar(&opts.storePath, "store", defaultStorePath(), "path to the local store")

	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(out)

	root.AddCommand(
		versionCmd(buildVersion, buildDate),
		registerCmd(opts),
		loginCmd(opts),
		addCmd(opts),
		listCmd(opts),
		getCmd(opts),
		deleteCmd(opts),
		syncCmd(opts),
	)
	return root.ExecuteContext(ctx)
}

func versionCmd(buildVersion, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print build version and date",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("Build version: %s\n", orNA(buildVersion))
			cmd.Printf("Build date: %s\n", orNA(buildDate))
			return nil
		},
	}
}

func registerCmd(opts *options) *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "create an account on the server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			master, err := readMasterPassword(cmd, true)
			if err != nil {
				return err
			}
			store, client, err := open(opts)
			if err != nil {
				return err
			}
			defer closeAll(store, client)

			vault, err := app.Register(cmd.Context(), client, store, login, master)
			if err != nil {
				return err
			}
			cmd.Printf("registered as %s\n", vault.Login())
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func loginCmd(opts *options) *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "sign in and synchronize the local store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			master, err := readMasterPassword(cmd, false)
			if err != nil {
				return err
			}
			store, client, err := open(opts)
			if err != nil {
				return err
			}
			defer closeAll(store, client)

			vault, err := app.Login(cmd.Context(), client, store, login, master)
			if err != nil {
				return err
			}
			result, err := vault.Sync(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Printf("signed in as %s, pulled %d records\n", vault.Login(), result.Pulled)
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func addCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "add a new secret",
	}
	cmd.AddCommand(addCredentialsCmd(opts), addTextCmd(opts), addBinaryCmd(opts), addCardCmd(opts))
	return cmd
}

func addCredentialsCmd(opts *options) *cobra.Command {
	var name, meta, login, password string

	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "add a login and password pair",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return addSecret(cmd, opts, &model.Secret{
				Kind:        model.KindCredentials,
				Name:        name,
				Meta:        meta,
				Credentials: &model.Credentials{Login: login, Password: password},
			})
		},
	}
	bindNameMeta(cmd, &name, &meta)
	cmd.Flags().StringVar(&login, "login", "", "stored login")
	cmd.Flags().StringVar(&password, "password", "", "stored password")
	return cmd
}

func addTextCmd(opts *options) *cobra.Command {
	var name, meta, text, file string

	cmd := &cobra.Command{
		Use:   "text",
		Short: "add arbitrary text",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file != "" {
				data, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read text file: %w", err)
				}
				text = string(data)
			}
			return addSecret(cmd, opts, &model.Secret{
				Kind: model.KindText,
				Name: name,
				Meta: meta,
				Text: text,
			})
		},
	}
	bindNameMeta(cmd, &name, &meta)
	cmd.Flags().StringVar(&text, "text", "", "text to store")
	cmd.Flags().StringVar(&file, "file", "", "read text from file")
	return cmd
}

func addBinaryCmd(opts *options) *cobra.Command {
	var name, meta, file string

	cmd := &cobra.Command{
		Use:   "binary",
		Short: "add arbitrary binary data",
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			return addSecret(cmd, opts, &model.Secret{
				Kind:   model.KindBinary,
				Name:   name,
				Meta:   meta,
				Binary: data,
			})
		},
	}
	bindNameMeta(cmd, &name, &meta)
	cmd.Flags().StringVar(&file, "file", "", "file to store")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func addCardCmd(opts *options) *cobra.Command {
	var name, meta, number, holder, expires, cvv string

	cmd := &cobra.Command{
		Use:   "card",
		Short: "add bank card data",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return addSecret(cmd, opts, &model.Secret{
				Kind: model.KindCard,
				Name: name,
				Meta: meta,
				Card: &model.Card{Number: number, Holder: holder, Expires: expires, CVV: cvv},
			})
		},
	}
	bindNameMeta(cmd, &name, &meta)
	cmd.Flags().StringVar(&number, "number", "", "card number")
	cmd.Flags().StringVar(&holder, "holder", "", "card holder")
	cmd.Flags().StringVar(&expires, "expires", "", "expiration date")
	cmd.Flags().StringVar(&cvv, "cvv", "", "verification code")
	return cmd
}

func listCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list stored secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			vault, cleanup, err := unlock(cmd, opts)
			if err != nil {
				return err
			}
			defer cleanup()

			secrets, err := vault.List()
			if err != nil {
				return err
			}
			if len(secrets) == 0 {
				cmd.Println("store is empty")
				return nil
			}
			for _, info := range secrets {
				mark := ""
				if info.Pending {
					mark = " (not synchronized)"
				}
				cmd.Printf("%s  %-12s %s%s\n", info.ID, info.Kind, info.Name, mark)
			}
			return nil
		},
	}
}

func getCmd(opts *options) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "show one secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vault, cleanup, err := unlock(cmd, opts)
			if err != nil {
				return err
			}
			defer cleanup()

			secret, err := vault.Get(args[0])
			if err != nil {
				return err
			}
			return printSecret(cmd, secret, out)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write binary data to file")
	return cmd
}

func deleteCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vault, cleanup, err := unlock(cmd, opts)
			if err != nil {
				return err
			}
			defer cleanup()

			if err := vault.Delete(args[0]); err != nil {
				return err
			}
			cmd.Println("deleted locally, run sync to publish the change")
			return nil
		},
	}
}

func syncCmd(opts *options) *cobra.Command {
	var resolve, id string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "exchange changes with the server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			vault, cleanup, err := unlock(cmd, opts)
			if err != nil {
				return err
			}
			defer cleanup()

			if resolve != "" {
				return resolveConflict(cmd, vault, resolve, id)
			}

			result, err := vault.Sync(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Printf("pulled %d, pushed %d\n", result.Pulled, result.Pushed)
			for _, conflict := range result.Conflicts {
				cmd.Printf("conflict %s\n", conflict.ID)
				cmd.Printf("  local:  %s\n", describe(conflict.Local))
				cmd.Printf("  server: %s\n", describe(conflict.Remote))
			}
			if len(result.Conflicts) > 0 {
				cmd.Println("run: gophkeeper sync --resolve local|remote --id <id>")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&resolve, "resolve", "", "resolve a conflict: local or remote")
	cmd.Flags().StringVar(&id, "id", "", "secret to resolve")
	return cmd
}

func resolveConflict(cmd *cobra.Command, vault *app.Vault, resolve, id string) error {
	if id == "" {
		return errors.New("--id is required to resolve a conflict")
	}
	switch resolve {
	case "local":
		if err := vault.ResolveLocal(cmd.Context(), id); err != nil {
			return err
		}
		cmd.Println("local version published")
	case "remote":
		if err := vault.ResolveRemote(id); err != nil {
			return err
		}
		cmd.Println("local version dropped")
	default:
		return fmt.Errorf("unknown resolution %q, use local or remote", resolve)
	}
	return nil
}

func addSecret(cmd *cobra.Command, opts *options, secret *model.Secret) error {
	vault, cleanup, err := unlock(cmd, opts)
	if err != nil {
		return err
	}
	defer cleanup()

	id, err := vault.Add(secret)
	if err != nil {
		return err
	}
	cmd.Printf("%s\n", id)
	return nil
}

func printSecret(cmd *cobra.Command, secret *model.Secret, out string) error {
	cmd.Printf("name: %s\n", secret.Name)
	cmd.Printf("kind: %s\n", secret.Kind)
	if secret.Meta != "" {
		cmd.Printf("meta: %s\n", secret.Meta)
	}

	switch secret.Kind {
	case model.KindCredentials:
		cmd.Printf("login: %s\npassword: %s\n", secret.Credentials.Login, secret.Credentials.Password)
	case model.KindText:
		cmd.Printf("text: %s\n", secret.Text)
	case model.KindCard:
		cmd.Printf("number: %s\nholder: %s\nexpires: %s\ncvv: %s\n",
			secret.Card.Number, secret.Card.Holder, secret.Card.Expires, secret.Card.CVV)
	case model.KindBinary:
		if out == "" {
			cmd.Printf("binary: %d bytes, use --out to save\n", len(secret.Binary))
			return nil
		}
		if err := os.WriteFile(out, secret.Binary, 0o600); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		cmd.Printf("binary written to %s\n", out)
	}
	return nil
}

func describe(secret *model.Secret) string {
	if secret == nil {
		return "deleted"
	}
	return fmt.Sprintf("%s %q", secret.Kind, secret.Name)
}

// unlock открывает локальное хранилище и соединение с сервером.
func unlock(cmd *cobra.Command, opts *options) (*app.Vault, func(), error) {
	master, err := readMasterPassword(cmd, false)
	if err != nil {
		return nil, nil, err
	}
	store, client, err := open(opts)
	if err != nil {
		return nil, nil, err
	}

	vault, err := app.Unlock(client, store, master)
	if err != nil {
		closeAll(store, client)
		return nil, nil, err
	}
	return vault, func() { closeAll(store, client) }, nil
}

func open(opts *options) (*localstore.Store, *remote.Client, error) {
	store, err := localstore.Open(opts.storePath)
	if err != nil {
		return nil, nil, err
	}
	client, err := remote.Dial(opts.address, opts.caCert)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, client, nil
}

func closeAll(store *localstore.Store, client *remote.Client) {
	if client != nil {
		_ = client.Close()
	}
	if store != nil {
		_ = store.Close()
	}
}

// readMasterPassword спрашивает мастер-пароль без эха. Значение никуда не
// сохраняется: из него выводится ключ, который живёт только в памяти процесса.
func readMasterPassword(cmd *cobra.Command, confirm bool) (string, error) {
	if value := os.Getenv(masterPasswordEnv); value != "" {
		return value, nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("master password is required: set %s or run in a terminal", masterPasswordEnv)
	}

	cmd.Print("master password: ")
	first, err := term.ReadPassword(fd)
	cmd.Println()
	if err != nil {
		return "", fmt.Errorf("read master password: %w", err)
	}
	if confirm {
		cmd.Print("repeat master password: ")
		second, err := term.ReadPassword(fd)
		cmd.Println()
		if err != nil {
			return "", fmt.Errorf("read master password: %w", err)
		}
		if string(first) != string(second) {
			return "", errors.New("passwords do not match")
		}
	}

	master := strings.TrimSpace(string(first))
	if master == "" {
		return "", errors.New("master password is empty")
	}
	return master, nil
}

func bindNameMeta(cmd *cobra.Command, name, meta *string) {
	cmd.Flags().StringVar(name, "name", "", "secret name")
	cmd.Flags().StringVar(meta, "meta", "", "arbitrary text metadata")
	_ = cmd.MarkFlagRequired("name")
}

func defaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(storeDirName, storeFileName)
	}
	return filepath.Join(home, storeDirName, storeFileName)
}

func orNA(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}
