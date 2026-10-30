.PHONY: webui build test

webui:
	cd webui && npm run build

build: webui
	go build -o proxy .

test:
	go test -count=1 ./...
