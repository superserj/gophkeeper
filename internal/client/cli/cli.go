// Package cli описывает команды клиента GophKeeper.
package cli

import (
	"bufio"
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

// secretFilePerm — права на файлы с расшифрованными данными.
const secretFilePerm = 0o600

// options — общие флаги всех команд и общий буфер ввода.
type options struct {
	address   string
	caCert    string
	storePath string
	input     *bufio.Reader
}

// Execute выполняет команду, разобрав аргументы командной строки.
func Execute(ctx context.Context, buildVersion, buildDate string) error {
	return Run(ctx, os.Args[1:], os.Stdin, os.Stdout, buildVersion, buildDate)
}

// Run выполняет команду с заданными аргументами, вводом и выводом. Отдельная
// функция нужна тестам: они гоняют команды без подмены глобального состояния
// процесса.
func Run(ctx context.Context, args []string, in io.Reader, out io.Writer, buildVersion, buildDate string) error {
	// Буфер чтения один на запуск: отдельный буфер на каждое значение забирал бы
	// в себя следующие строки, и второе значение терялось бы.
	opts := &options{input: bufio.NewReader(in)}

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
	root.SetIn(in)
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
			return writeLines(cmd.OutOrStdout(),
				fmt.Sprintf("Build version: %s", orNA(buildVersion)),
				fmt.Sprintf("Build date: %s", orNA(buildDate)),
			)
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
			return writeLines(cmd.OutOrStdout(), fmt.Sprintf("registered as %s", vault.Login()))
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
			if err := writeLines(cmd.OutOrStdout(),
				fmt.Sprintf("signed in as %s, pulled %d records", vault.Login(), result.Pulled)); err != nil {
				return err
			}
			// Конфликты бывают и при входе: локальная правка могла остаться
			// неотправленной, и промолчать о ней значит потерять её для пользователя.
			return printSyncResult(cmd, result)
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
	var name, meta, login string

	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "add a login and password pair",
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := readSecretValue(cmd, opts, "password: ")
			if err != nil {
				return err
			}
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
	return cmd
}

func addTextCmd(opts *options) *cobra.Command {
	var name, meta, file string

	cmd := &cobra.Command{
		Use:   "text",
		Short: "add arbitrary text",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Текст — такой же секрет, как пароль, и флагом не принимается:
			// аргументы видны в списке процессов и остаются в истории оболочки.
			var text string
			if file != "" {
				data, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read text file: %w", err)
				}
				text = string(data)
			} else {
				value, err := readSecretValue(cmd, opts, "text: ")
				if err != nil {
					return err
				}
				text = value
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
	var name, meta, holder, expires string

	cmd := &cobra.Command{
		Use:   "card",
		Short: "add bank card data",
		RunE: func(cmd *cobra.Command, _ []string) error {
			number, err := readSecretValue(cmd, opts, "card number: ")
			if err != nil {
				return err
			}
			cvv, err := readSecretValue(cmd, opts, "verification code: ")
			if err != nil {
				return err
			}
			return addSecret(cmd, opts, &model.Secret{
				Kind: model.KindCard,
				Name: name,
				Meta: meta,
				Card: &model.Card{Number: number, Holder: holder, Expires: expires, CVV: cvv},
			})
		},
	}
	bindNameMeta(cmd, &name, &meta)
	cmd.Flags().StringVar(&holder, "holder", "", "card holder")
	cmd.Flags().StringVar(&expires, "expires", "", "expiration date")
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
			w := cmd.OutOrStdout()
			if len(secrets) == 0 {
				return writeLines(w, "store is empty")
			}
			for _, info := range secrets {
				mark := ""
				if info.Pending {
					mark = " (not synchronized)"
				}
				if err := writeLines(w, fmt.Sprintf("%s  %-12s %s%s", info.ID, info.Kind, info.Name, mark)); err != nil {
					return err
				}
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
			return writeLines(cmd.OutOrStdout(), "deleted locally, run sync to publish the change")
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
			if err := writeLines(cmd.OutOrStdout(),
				fmt.Sprintf("pulled %d, pushed %d", result.Pulled, result.Pushed)); err != nil {
				return err
			}
			return printSyncResult(cmd, result)
		},
	}
	cmd.Flags().StringVar(&resolve, "resolve", "", "resolve a conflict: local or remote")
	cmd.Flags().StringVar(&id, "id", "", "secret to resolve")
	return cmd
}

// printSyncResult показывает конфликты и способ их разрешения.
func printSyncResult(cmd *cobra.Command, result app.SyncResult) error {
	if len(result.Conflicts) == 0 {
		return nil
	}

	w := cmd.OutOrStdout()
	for _, conflict := range result.Conflicts {
		err := writeLines(w,
			fmt.Sprintf("conflict %s", conflict.ID),
			fmt.Sprintf("  local:  %s", describe(conflict.Local)),
			fmt.Sprintf("  server: %s", describe(conflict.Remote)),
		)
		if err != nil {
			return err
		}
	}
	return writeLines(w, "run: gophkeeper sync --resolve local|remote --id <id>")
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
		return writeLines(cmd.OutOrStdout(), "local version published")
	case "remote":
		if err := vault.ResolveRemote(id); err != nil {
			return err
		}
		return writeLines(cmd.OutOrStdout(), "local version dropped")
	default:
		return fmt.Errorf("unknown resolution %q, use local or remote", resolve)
	}
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
	return writeLines(cmd.OutOrStdout(), id)
}

// printSecret печатает расшифрованную запись. Ошибки записи здесь возвращаются,
// а не проглатываются: иначе при переполненном диске или оборванном выводе
// команда сообщила бы об успехе, показав пользователю неполные данные.
func printSecret(cmd *cobra.Command, secret *model.Secret, out string) error {
	w := cmd.OutOrStdout()

	if err := writeLines(w,
		fmt.Sprintf("name: %s", secret.Name),
		fmt.Sprintf("kind: %s", secret.Kind),
	); err != nil {
		return err
	}
	if secret.Meta != "" {
		if err := writeLines(w, fmt.Sprintf("meta: %s", secret.Meta)); err != nil {
			return err
		}
	}

	switch secret.Kind {
	case model.KindCredentials:
		return writeLines(w,
			fmt.Sprintf("login: %s", secret.Credentials.Login),
			fmt.Sprintf("password: %s", secret.Credentials.Password),
		)
	case model.KindText:
		return writeLines(w, fmt.Sprintf("text: %s", secret.Text))
	case model.KindCard:
		return writeLines(w,
			fmt.Sprintf("number: %s", secret.Card.Number),
			fmt.Sprintf("holder: %s", secret.Card.Holder),
			fmt.Sprintf("expires: %s", secret.Card.Expires),
			fmt.Sprintf("cvv: %s", secret.Card.CVV),
		)
	case model.KindBinary:
		if out == "" {
			return writeLines(w, fmt.Sprintf("binary: %d bytes, use --out to save", len(secret.Binary)))
		}
		if err := writeSecretFile(out, secret.Binary); err != nil {
			return err
		}
		return writeLines(w, fmt.Sprintf("binary written to %s", out))
	}
	return nil
}

// writeLines пишет строки и сообщает о первой же ошибке вывода.
func writeLines(w io.Writer, lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}

// writeSecretFile кладёт расшифрованные данные в новый файл с правами 0600 и
// подменяет им целевой: запись поверх существующего файла сохранила бы его
// прежние права, и секрет стал бы доступен другим пользователям системы.
func writeSecretFile(path string, data []byte) error {
	temp := path + ".tmp"
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, secretFilePerm)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return fmt.Errorf("write file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("close file: %w", err)
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("replace file: %w", err)
	}
	return nil
}

// readSecretValue спрашивает значение, которое нельзя передавать флагом:
// аргументы командной строки видны в списке процессов и остаются в истории
// оболочки.
func readSecretValue(cmd *cobra.Command, opts *options, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		cmd.Print(prompt)
		value, err := term.ReadPassword(fd)
		cmd.Println()
		if err != nil {
			return "", fmt.Errorf("read value: %w", err)
		}
		return string(value), nil
	}

	line, err := opts.input.ReadString('\n')
	if errors.Is(err, io.EOF) && line == "" {
		return "", fmt.Errorf("value for %q is not provided", strings.TrimSuffix(prompt, ": "))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read value: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
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

	// Пароль не обрезается: значение из окружения тоже берётся как есть, и
	// обрезка пробелов развела бы ключи, выведенные из одного и того же пароля.
	master := string(first)
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
