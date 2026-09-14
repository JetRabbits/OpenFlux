IMAGE ?= ghcr.io/jetrabbits/openflux
TAG ?= latest
PLATFORMS ?= linux/amd64

.PHONY: docker-build docker-push docker-run-client build build-linux-amd64 build-android-so

docker-build:
	IMAGE=$(IMAGE) TAG=$(TAG) PLATFORMS=$(PLATFORMS) PUSH=false ./build_docker.sh

docker-push:
	IMAGE=$(IMAGE) TAG=$(TAG) PLATFORMS=$(PLATFORMS) PUSH=true ./build_docker.sh

docker-run-client:
	docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW --network host \
		$(IMAGE):$(TAG) --client --transport yandex --url '$(OPENFLUX_URL)' --socks5 '$(SOCKS5_ADDR)' --debug

build:
	go build -trimpath -ldflags="-s -w -checklinkname=0" -o output/openflux .

build-linux-amd64:
	mkdir -p output/linux/amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -checklinkname=0" -o output/linux/amd64/openflux .

build-android-so:
	./build_android_so.sh
