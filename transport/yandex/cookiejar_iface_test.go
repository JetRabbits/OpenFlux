package yandex

import (
	"github.com/JetRabbits/OpenFlux/transport"
)

var _ transport.CookieExchanger = (*YandexDocsTransport)(nil)
