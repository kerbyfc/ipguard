// Package config читает настройки сторожа: файл viper в каталоге установки, окружение и
// встроенные значения нынешнего контракта — источник проверки, тайминги и граница охраны.
// Ожидаемого адреса среди встроенных нет: он у каждой машины свой и задаётся установкой.
// Битый файл или поле вне допустимого — ошибка, а не тихий откат к значениям по умолчанию:
// сторож доступа не должен молча работать не по той настройке.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/hosts"
)

const (
	// FileName — имя файла настроек в каталоге установки.
	FileName = "ipguard.yaml"
	// DirName — каталог установки в домашнем каталоге пользователя.
	DirName = ".local/share/claude-ipguard"
	// LogFileName — имя журнала по умолчанию.
	LogFileName = "proxy.log"
	// SeenHostsFileName — имя файла встреченных хостов по умолчанию: он лежит рядом с
	// журналом, в каталоге установки.
	SeenHostsFileName = "hosts.tsv"

	// SecretEnv — окружение с секретом доступа к прокси.
	SecretEnv = "IPGUARD_SECRET"

	// DefaultCheckURL — единственный хост проверки.
	DefaultCheckURL = "https://icanhazip.com/"
	// DefaultAttemptTimeout — таймаут одной попытки. В живом журнале владельца полный цикл
	// проверки доходил до 24 с, а источник не укладывался в прежние 10 с; 30 с дают запас,
	// не растягивая ожидание: повторы идут внутри бюджета.
	DefaultAttemptTimeout = 30 * time.Second
	// DefaultBudget — предел ожидания вердикта: цифра прежнего ipcheck.sh, ниже неё не
	// опускаемся.
	DefaultBudget = 540 * time.Second
	// DefaultListenAddress — слушатель только на loopback.
	DefaultListenAddress = "127.0.0.1"
	// DefaultListenPort — порт слушателя.
	DefaultListenPort = 8787
	// DefaultLogMaxBytes — предел размера журнала, после которого он ротируется.
	DefaultLogMaxBytes = 5 << 20
	// DefaultLogKeep — сколько прежних файлов журнала хранится.
	DefaultLogKeep = 3

	maxPort = 65535
)

// ErrSettings — негодные настройки: битый файл или поле вне допустимого.
var ErrSettings = errors.New("ipguard settings are invalid")

// ErrVerdictTTLRemoved — в настройках остался ключ снятой настройки. Трафик не идёт по
// завершённой проверке, поэтому сроку годности нечего ограничивать.
var ErrVerdictTTLRemoved = errors.New(
	"verdict_ttl was removed: a completed check's verdict is never reused, delete the key",
)

// ErrGuardedHostsRemoved — в настройках остался ключ снятой настройки. Граница охраны
// перевёрнута: вердикта ждёт любой хост, кроме исключений, и перечислять охраняемые нечего.
var ErrGuardedHostsRemoved = errors.New(
	"guarded_hosts was removed: every host waits for a verdict except unguarded_hosts, delete the key" +
		" (ipguard install rewrites it)",
)

// Settings — настройки сторожа.
type Settings struct {
	ExpectedIP     string          `mapstructure:"expected_ip"`
	CheckURL       string          `mapstructure:"check_url"`
	UnguardedHosts []string        `mapstructure:"unguarded_hosts"`
	AttemptTimeout time.Duration   `mapstructure:"attempt_timeout"`
	RetryDelays    []time.Duration `mapstructure:"retry_delays"`
	Budget         time.Duration   `mapstructure:"budget"`
	ListenAddress  string          `mapstructure:"listen_address"`
	ListenPort     int             `mapstructure:"listen_port"`
	Secret         string          `mapstructure:"secret"`
	UpstreamProxy  string          `mapstructure:"upstream_proxy"`
	LogPath        string          `mapstructure:"log_path"`
	SeenHostsPath  string          `mapstructure:"seen_hosts_path"`
	LogMaxBytes    int64           `mapstructure:"log_max_bytes"`
	LogKeep        int             `mapstructure:"log_keep"`
}

// ListenAddr — адрес слушателя для net.Listen.
func (settings Settings) ListenAddr() string {
	return net.JoinHostPort(settings.ListenAddress, strconv.Itoa(settings.ListenPort))
}

// Validate проверяет каждое поле: отказ называет поле и причину.
func (settings Settings) Validate() error {
	err := settings.validateCheck()
	if err != nil {
		return err
	}

	err = settings.validateListener()
	if err != nil {
		return err
	}

	return settings.validateStorage()
}

// validateCheck проверяет адрес, источник, тайминги и границу охраны.
func (settings Settings) validateCheck() error {
	// Встроенного адреса нет: он у каждой машины свой, а сторож пускал бы трафик не по той
	// настройке. Пустое поле называется своим отказом — «"" is not an IP address» говорило бы
	// о формате того, чего нет.
	if settings.ExpectedIP == "" {
		return fmt.Errorf(
			"%w: expected_ip is not set: run `ipguard install` or add it to the settings file",
			ErrSettings,
		)
	}

	if net.ParseIP(settings.ExpectedIP) == nil {
		return fmt.Errorf("%w: expected_ip %q is not an IP address", ErrSettings, settings.ExpectedIP)
	}

	err := validateURL("check_url", settings.CheckURL)
	if err != nil {
		return err
	}

	_, err = hosts.New(settings.UnguardedHosts)
	if err != nil {
		return fmt.Errorf("%w: unguarded_hosts: %w", ErrSettings, err)
	}

	if settings.AttemptTimeout <= 0 {
		return fmt.Errorf("%w: attempt_timeout must be positive, got %s", ErrSettings, settings.AttemptTimeout)
	}

	err = settings.validateRetryDelays()
	if err != nil {
		return err
	}

	return settings.validateTimings()
}

// validateRetryDelays проверяет расписание повторов.
func (settings Settings) validateRetryDelays() error {
	if len(settings.RetryDelays) == 0 {
		return fmt.Errorf("%w: retry_delays must list at least one delay", ErrSettings)
	}

	for index, delay := range settings.RetryDelays {
		if delay <= 0 {
			return fmt.Errorf("%w: retry_delays[%d] must be positive, got %s", ErrSettings, index, delay)
		}
	}

	return nil
}

// validateTimings проверяет бюджет.
func (settings Settings) validateTimings() error {
	if settings.Budget <= 0 {
		return fmt.Errorf("%w: budget must be positive, got %s", ErrSettings, settings.Budget)
	}

	if settings.Budget < settings.AttemptTimeout {
		return fmt.Errorf(
			"%w: budget %s is shorter than attempt_timeout %s",
			ErrSettings, settings.Budget, settings.AttemptTimeout,
		)
	}

	return nil
}

// validateStorage проверяет верхний прокси и журнал.
func (settings Settings) validateStorage() error {
	if settings.UpstreamProxy != "" {
		err := validateUpstream(settings.UpstreamProxy)
		if err != nil {
			return err
		}
	}

	if settings.LogPath == "" {
		return fmt.Errorf("%w: log_path is required", ErrSettings)
	}

	if settings.SeenHostsPath == "" {
		return fmt.Errorf("%w: seen_hosts_path is required", ErrSettings)
	}

	if settings.LogMaxBytes <= 0 {
		return fmt.Errorf("%w: log_max_bytes must be positive, got %d", ErrSettings, settings.LogMaxBytes)
	}

	if settings.LogKeep < 1 {
		return fmt.Errorf("%w: log_keep must keep at least one file, got %d", ErrSettings, settings.LogKeep)
	}

	return nil
}

// RequireSecret — требование слушателя: без секрета любой локальный процесс ходил бы наружу
// через этот порт, поэтому прокси без него не поднимается. Разовой проверке секрет не нужен.
func (settings Settings) RequireSecret() error {
	if settings.Secret != "" {
		return nil
	}

	return fmt.Errorf(
		"%w: secret is required (field `secret` of the settings file or environment %s)",
		ErrSettings, SecretEnv,
	)
}

// validateListener держит слушателя на loopback: наружу сторож не слушает никогда.
func (settings Settings) validateListener() error {
	address := net.ParseIP(settings.ListenAddress)
	if address == nil {
		return fmt.Errorf("%w: listen_address %q is not an IP address", ErrSettings, settings.ListenAddress)
	}

	if !address.IsLoopback() {
		return fmt.Errorf("%w: listen_address %q is not a loopback address", ErrSettings, settings.ListenAddress)
	}

	if settings.ListenPort < 1 || settings.ListenPort > maxPort {
		return fmt.Errorf("%w: listen_port %d is out of range 1..%d", ErrSettings, settings.ListenPort, maxPort)
	}

	return nil
}

// expandPaths раскрывает ведущий `~` в путях файлов: у launchd и планировщика Windows
// рабочий каталог не домашний, и нераскрытая тильда уводила бы журнал и таблицу хостов в
// случайный каталог.
func (settings Settings) expandPaths() (Settings, error) {
	expanded, err := ExpandHome(settings.LogPath)
	if err != nil {
		return settings, err
	}

	settings.LogPath = expanded

	expanded, err = ExpandHome(settings.SeenHostsPath)
	if err != nil {
		return settings, err
	}

	settings.SeenHostsPath = expanded

	return settings, nil
}

// DefaultRetryDelays — паузы повторов нынешнего контракта: 1, 2, 4, 8, 10 с, дальше по 10 с.
func DefaultRetryDelays() []time.Duration {
	return []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		10 * time.Second,
	}
}

// DefaultUnguardedHosts — белый список по умолчанию: пустой. Хост проверки и локальные
// цели в коде, а не в настройке: их исключение — инвариант сторожа, а не решение владельца,
// и снять его правкой файла нельзя.
func DefaultUnguardedHosts() []string {
	return []string{}
}

// Defaults — встроенные значения: тайминги и граница охраны нынешнего контракта. Ни секрета,
// ни ожидаемого адреса среди них нет: встроенный секрет знали бы все, а встроенный адрес
// пускал бы трафик не по настройке этой машины.
func Defaults() Settings {
	return Settings{
		ExpectedIP:     "",
		CheckURL:       DefaultCheckURL,
		UnguardedHosts: DefaultUnguardedHosts(),
		AttemptTimeout: DefaultAttemptTimeout,
		RetryDelays:    DefaultRetryDelays(),
		Budget:         DefaultBudget,
		ListenAddress:  DefaultListenAddress,
		ListenPort:     DefaultListenPort,
		Secret:         "",
		UpstreamProxy:  "",
		LogPath:        filepath.Join(DefaultDir(), LogFileName),
		SeenHostsPath:  filepath.Join(DefaultDir(), SeenHostsFileName),
		LogMaxBytes:    DefaultLogMaxBytes,
		LogKeep:        DefaultLogKeep,
	}
}

// DefaultDir — каталог установки: `~/.local/share/claude-ipguard`.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return DirName
	}

	return filepath.Join(home, DirName)
}

// DefaultPath — файл настроек в каталоге установки.
func DefaultPath() string {
	return filepath.Join(DefaultDir(), FileName)
}

// ExpandHome раскрывает ведущий `~` в путь домашнего каталога: настройки и команды запуска
// пишут путь с тильдой, а у launchd и планировщика Windows рабочий каталог не домашний, и
// нераскрытая тильда уводила бы журнал в случайный каталог. `~user` не поддержан — это отказ,
// а не путь, созданный рядом.
func ExpandHome(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}

	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return "", fmt.Errorf("%w: path %q: only a leading ~ for the current user is supported", ErrSettings, path)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: path %q: %w", ErrSettings, path, err)
	}

	if path == "~" {
		return home, nil
	}

	return filepath.Join(home, path[2:]), nil
}

// UnguardedHostsSet — назван ли unguarded_hosts в файле настроек. Нужен установке и команде
// белого списка: отсутствующий ключ дописывается, а уже заданный список владельца не трогается.
func UnguardedHostsSet(path string) (bool, error) {
	_, set, err := UnguardedHostsOf(path)

	return set, err
}

// UnguardedHostsOf читает белый список из файла тем же разбором, каким его читает служба, и
// говорит, назван ли ключ. Им команда белого списка и установка проверяют свою правку до
// переименования временного файла: правка, после которой настройки не читаются, не должна
// доходить до файла службы.
func UnguardedHostsOf(path string) ([]string, bool, error) {
	path, err := ExpandHome(path)
	if err != nil {
		return nil, false, err
	}

	reader := viper.New()
	reader.SetConfigFile(path)
	reader.SetConfigType(strings.TrimPrefix(filepath.Ext(FileName), "."))

	err = reader.ReadInConfig()
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrSettings, path, err)
	}

	if !reader.IsSet("unguarded_hosts") {
		return nil, false, nil
	}

	return reader.GetStringSlice("unguarded_hosts"), true, nil
}

// Load читает настройки: файла нет — встроенные значения; файл есть и битый — ошибка.
// Секрет берётся и из окружения IPGUARD_SECRET, значение файла сильнее.
func Load(path string) (Settings, error) {
	settings := Defaults()

	path, err := ExpandHome(path)
	if err != nil {
		return settings, err
	}

	reader := viper.New()
	reader.SetConfigFile(path)
	reader.SetConfigType(strings.TrimPrefix(filepath.Ext(FileName), "."))

	_, err = os.Stat(path)

	switch {
	case err == nil:
		readErr := reader.ReadInConfig()
		if readErr != nil {
			return settings, fmt.Errorf("%w: %s: %w", ErrSettings, path, readErr)
		}

		unmarshalErr := decodeSettings(reader, &settings)
		if unmarshalErr != nil {
			return settings, fmt.Errorf("%w: %s: %w", ErrSettings, path, unmarshalErr)
		}
	case os.IsNotExist(err):
	default:
		return settings, fmt.Errorf("%w: %s: %w", ErrSettings, path, err)
	}

	if settings.Secret == "" {
		settings.Secret = os.Getenv(SecretEnv)
	}

	settings, err = settings.expandPaths()
	if err != nil {
		return settings, err
	}

	err = settings.Validate()
	if err != nil {
		return settings, err
	}

	return settings, nil
}

// decodeSettings разбирает файл настроек и отказывает на ключи снятых настроек. Опечатка в
// имени поля — тоже отказ (ErrorUnused), а не значение по умолчанию.
func decodeSettings(reader *viper.Viper, settings *Settings) error {
	// Трафик не идёт по завершённой проверке, поэтому сроку годности нечего ограничивать;
	// оставшийся ключ называет причину, а не молчит.
	if reader.InConfig("verdict_ttl") {
		return ErrVerdictTTLRemoved
	}

	// Граница перевёрнута: охраняемые хосты не перечисляются, и прежний список молча не
	// превращается в белый — иначе сторож пускал бы мимо проверки ровно хосты Claude.
	if reader.InConfig("guarded_hosts") {
		return ErrGuardedHostsRemoved
	}

	err := reader.Unmarshal(settings, func(decoder *mapstructure.DecoderConfig) {
		decoder.ErrorUnused = true
	})
	if err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}

	return nil
}

// validateUpstream требует у верхнего прокси схему http: TLS до верхнего прокси сторож не
// умеет, и тихо ходить в обход такой настройки он не должен.
func validateUpstream(raw string) error {
	err := validateURL("upstream_proxy", raw)
	if err != nil {
		return err
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: upstream_proxy %q: %w", ErrSettings, raw, err)
	}

	if parsed.Scheme != "http" {
		return fmt.Errorf(
			"%w: upstream_proxy %q must use scheme http: TLS to the upstream proxy is not supported",
			ErrSettings, raw,
		)
	}

	return nil
}

// validateURL требует абсолютный http(s)-адрес.
func validateURL(field, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s %q: %w", ErrSettings, field, raw, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %s %q must be an http or https URL", ErrSettings, field, raw)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%w: %s %q has no host", ErrSettings, field, raw)
	}

	return nil
}
