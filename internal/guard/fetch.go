package guard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxBodySize = 1 << 20

// FetchFunc — одна попытка узнать внешний IP.
type FetchFunc func(ctx context.Context, endpoint, proxy string) (string, error)

// FetchIP запрашивает внешний IP у хоста проверки. Пустой proxy — прямое соединение;
// окружение процесса не читается, верхний прокси приходит из настроек.
func FetchIP(ctx context.Context, endpoint, proxy string) (string, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return "", fmt.Errorf("%w: default transport has unexpected type", ErrFetch)
	}

	cloned := transport.Clone()
	cloned.Proxy = nil
	cloned.DisableKeepAlives = true

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrProxy, err)
		}

		cloned.Proxy = http.ProxyURL(proxyURL)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFetch, err)
	}

	client := &http.Client{
		Transport: cloned,
		// Редирект не ответ хоста проверки: по нему тело пришло бы с другого адреса, а его
		// содержимое сторож принял бы за внешний IP. Отказ, а не переход.
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirect to %s", ErrHTTPStatus, request.URL.Redacted())
		},
		Jar:     nil,
		Timeout: 0,
	}

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFetch, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("%w: %s", ErrHTTPStatus, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodySize))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFetch, err)
	}

	return strings.Join(strings.Fields(string(body)), ""), nil
}
