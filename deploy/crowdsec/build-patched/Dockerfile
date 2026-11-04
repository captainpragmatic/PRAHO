# The tag documents the toolchain; the digest fixes both supported platforms.
FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS dependencies
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
WORKDIR /src
COPY source.tar.gz /inputs/source.tar.gz
RUN tar -xzf /inputs/source.tar.gz --strip-components=1 -C /src \
    && cp go.mod /inputs/go.mod && cp go.sum /inputs/go.sum \
    && go mod download && go mod verify && go mod vendor \
    && cmp go.mod /inputs/go.mod && cmp go.sum /inputs/go.sum

FROM dependencies AS patched
ARG APPLY_PATCH=1
COPY patch.diff /inputs/patch.diff
COPY set_only_intervals_test.go /src/pkg/nftables/set_only_intervals_test.go
RUN if [ "$APPLY_PATCH" = 1 ]; then git apply --check /inputs/patch.diff && git apply --whitespace=error /inputs/patch.diff; fi

FROM patched AS tested
RUN --network=none go test -mod=vendor ./...

FROM tested AS compiled
RUN --network=none mkdir /out \
    && for arch in amd64 arm64; do \
      GOOS=linux GOARCH="$arch" go build -mod=vendor -trimpath -buildvcs=false -tags netgo \
        -ldflags '-s -w -buildid= -X github.com/crowdsecurity/go-cs-lib/version.Version=v0.0.36-praho.1 -X github.com/crowdsecurity/go-cs-lib/version.BuildDate=2026-11-03_00:00:00 -X github.com/crowdsecurity/go-cs-lib/version.Tag=4c315193cd4f19e3937cdee2f15183ec4d602f56+set-only-intervals-v1' \
        -o "/out/crowdsec-firewall-bouncer-$arch" .; \
    done \
    && sha256sum /inputs/source.tar.gz /inputs/patch.diff go.mod go.sum > /out/input-sha256.txt \
    && find vendor -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum > /out/vendor-tree-sha256.txt \
    && go env GOVERSION > /out/toolchain.txt \
    && go version -m /out/crowdsec-firewall-bouncer-amd64 > /out/build-info-amd64.txt \
    && go version -m /out/crowdsec-firewall-bouncer-arm64 > /out/build-info-arm64.txt

# Carry license texts and corresponding-source/build instructions beside binaries.
# File bytes and archive metadata remain independent of controller clocks/owners.
COPY PRAHO-LICENSE.md build.sh README.md Dockerfile /inputs/recipe/
RUN --network=none mkdir -p /notices/upstream /notices/praho /notices/go /notices/build \
    && cp LICENSE /notices/upstream/LICENSE \
    && cp /inputs/recipe/PRAHO-LICENSE.md /notices/praho/LICENSE.md \
    && cp /usr/local/go/LICENSE /usr/local/go/PATENTS /notices/go/ \
    && find vendor -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' -o -iname 'patents*' \) -exec cp --parents '{}' /notices/ \; \
    && cp /inputs/source.tar.gz /inputs/patch.diff /inputs/recipe/build.sh /inputs/recipe/README.md /inputs/recipe/Dockerfile /src/pkg/nftables/set_only_intervals_test.go /notices/build/ \
    && cp /out/input-sha256.txt /out/vendor-tree-sha256.txt /out/toolchain.txt /out/build-info-*.txt /notices/build/ \
    && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu -cf /out/license-notices.tar -C /notices . \
    && gzip -n /out/license-notices.tar

FROM scratch AS artifact
COPY --from=compiled /out/ /
