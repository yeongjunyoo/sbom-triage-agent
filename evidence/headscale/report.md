# SW 공급망 점검 보고서: headscale_e172c29360

자산: headscale, 담당 인프라운영, 사업 공통, 인터넷 노출 예, 데이터 등급 인증정보

| 단계 | 건수 |
|---|---:|
| SBOM 구성요소 | 259 |
| 스캐너 경보(중복 포함) | 133 |
| 패키지와 CVE 기준 고유 건 | 85 |
| 규칙 등급 1 실제 악용(KEV) / 2 / 3 / 4 | 0 / 10 / 22 / 53 |
| 에이전트 판단 | 40 |
| 조치 대상 OPEN | 4 |
| 사람 검토 REVIEW | 15 |
| 근거와 함께 닫음 CLOSE | 21 |

호출 그래프와 충돌해 닫지 않은 건 9건.

판단 80회(건당 독립 2회), 회당 평균 61초, 모델 비용 환산 8.85달러. KEV 판 1766건, EPSS 2026-11-01.

## 조치 대상

| 영향도 | 패키지 | 버전 | CVE | KEV | EPSS | 수정 버전 | 이유 |
|---|---|---|---|---|---:|---|---|
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2026-33814 |  | 0.008 | 0.53.0 | 코드에서 쓰임이 확인됨 |
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2026-78659 |  | 0.006 | 0.60.0 | 코드에서 쓰임이 확인됨 |
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2026-78663 |  | 0.006 | 0.60.0 | 코드에서 쓰임이 확인됨 |
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2026-78669 |  | 0.006 | 0.60.0 | 코드에서 쓰임이 확인됨 |

### golang.org/x/net CVE-2026-33814

- 회차별 판단: vulnerable, vulnerable
- 사유: 코드에서 쓰임이 확인됨
- 에이전트 설명: CVE-2026-33814 (GO-2026-4918) is an HTTP/2 client-side infinite loop. The transport loops writing CONTINUATION frames after it receives a SETTINGS frame with SETTINGS_MAX_FRAME_SIZE=0. It affects golang.org/x/net/http2 before v0.53.0 and the stdlib net/http before go1.25.10 (and go1.26.0 to before 1.26.3).

Presence: go.mod pins golang.org/x/net v0.32.0, which is below 0.53.0. The build toolchain is Go 1.23 (go.mod 'go 1.23.1', flake.nix buildGo123Module, Dockerfile.integration golang:1.23), whi
- 인용: go.mod:42 golang.org/x/net v0.32.0
- 인용: go.mod:3 go 1.23.1
- 인용: flake.nix:23 buildGo = pkgs.buildGo123Module;
- 인용: hscontrol/derp/derp.go:42 client := http.Client{

### golang.org/x/net CVE-2026-78659

- 회차별 판단: vulnerable, vulnerable
- 사유: 코드에서 쓰임이 확인됨
- 에이전트 설명: CVE-2026-78659 (NVD, published by security@golang.org) is an HTTP/2 resource-exhaustion flaw. A client can declare a very large number of Trailer fields over HTTP/2. The server allocates memory disproportionately and bypasses the MaxHeaderBytes and MaxHeaderValueCount limits. The affected x/net surface is golang.org/x/net/http2 (Framer.readMetaFrame, Server.ServeConn) before v0.60.0. This repository resolves golang.org/x/net to v0.32.0, which is in the affected range. First-party code hscontrol/
- 인용: go.mod:42 golang.org/x/net v0.32.0
- 인용: hscontrol/noise.go:14 "golang.org/x/net/http2"
- 인용: hscontrol/noise.go:107 noiseServer.http2Server = &http2.Server{}
- 인용: hscontrol/noise.go:109 noiseServer.http2Server.ServeConn(

### golang.org/x/net CVE-2026-78663

- 회차별 판단: vulnerable, vulnerable
- 사유: 코드에서 쓰임이 확인됨
- 에이전트 설명: CVE-2026-78663 (GO-2026-6612) is an HTTP/2 server flaw. It credits connection-level flow control twice for the same data, once when a client resets a stream and again when a handler reads the buffered data. A client can use this to exceed MaxReceiveBufferPerConnection. For golang.org/x/net/http2 the affected range is before v0.60.0, and the vulnerable symbols include Server.ServeConn. The repository pins golang.org/x/net v0.32.0 in go.mod and go.sum, so it is in range. hscontrol/noise.go imports
- 인용: go.mod:42 golang.org/x/net v0.32.0
- 인용: go.sum:585 golang.org/x/net v0.32.0 h1:ZqPmj8Kzc+Y6e0+skZsuACbx+wzMgo5MQsJh9Qd6aYI=
- 인용: hscontrol/noise.go:14 "golang.org/x/net/http2"
- 인용: hscontrol/noise.go:107 noiseServer.http2Server = &http2.Server{}

### golang.org/x/net CVE-2026-78669

- 회차별 판단: vulnerable, vulnerable
- 사유: 코드에서 쓰임이 확인됨
- 에이전트 설명: CVE-2026-78669 (GO-2026-6611) is an HTTP/2 resource-exhaustion flaw. A malicious peer opens many streams and sends many small SETTINGS frames with SETTINGS_INITIAL_WINDOW_SIZE values, which drives up CPU use. Affected: golang.org/x/net/http2 before v0.60.0, plus Go stdlib net/http before go1.26.9. This repository resolves golang.org/x/net to v0.32.0 in go.mod and go.sum. That is inside the affected range. There is no replace directive and no vendored copy. First-party code in hscontrol/noise.go 
- 인용: go.mod:42 golang.org/x/net v0.32.0
- 인용: go.sum:585 golang.org/x/net v0.32.0 h1:ZqPmj8Kzc+Y6e0+skZsuACbx+wzMgo5MQsJh9Qd6aYI=
- 인용: hscontrol/noise.go:14 "golang.org/x/net/http2"
- 인용: hscontrol/noise.go:107 noiseServer.http2Server = &http2.Server{}

## 사람 검토 필요

| 영향도 | 패키지 | 버전 | CVE | KEV | EPSS | 수정 버전 | 이유 |
|---|---|---|---|---|---:|---|---|
| 중 4 | google.golang.org/grpc | v1.69.0 | CVE-2026-33186 |  | 0.016 | 1.79.3 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | golang.org/x/oauth2 | v0.24.0 | CVE-2025-22868 |  | 0.009 | 0.27.0 | 근거 재현 검사 실패: 범위를 읽지 못해 저장소 전체로 다시 찾으니 3건: google\.golang\.org/api|cloud\.google\.com|oauth |
| 중 4 | github.com/golang-jwt/jwt/v5 | v5.2.1 | CVE-2025-30204 |  | 0.008 | 5.2.2 | 에이전트가 근거 부족으로 판단을 보류함 |
| 중 4 | github.com/opencontainers/runc | v1.2.3 | CVE-2025-52565 |  | 0.008 | 1.2.8, 1.3.3 | 저장소 글 차단: 사람이 쓴 글을 근거로 인용: integration/dockertestutil/config.go |
| 중 4 | github.com/opencontainers/runc | v1.2.3 | CVE-2025-52881 |  | 0.008 | 1.2.8, 1.3.3 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | github.com/go-jose/go-jose/v3 | v3.0.3 | CVE-2026-34986 |  | 0.007 | 3.0.5 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | github.com/go-jose/go-jose/v4 | v4.0.2 | CVE-2026-34986 |  | 0.007 | 4.1.4 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | google.golang.org/grpc | v1.69.0 | CVE-2026-84445 |  | 0.006 | 1.82.2, 1.83.2 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | google.golang.org/grpc | v1.69.0 | CVE-2026-84304 |  | 0.006 | 1.83.1 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | github.com/go-jose/go-jose/v3 | v3.0.3 | CVE-2026-116587 |  | 0.004 |  | 저장소 글 차단: 사람이 쓴 글을 근거로 인용: config-example.yaml |
| 중 4 | github.com/go-jose/go-jose/v4 | v4.0.2 | CVE-2026-116587 |  | 0.004 | 4.1.6 | 저장소 글 차단: 사람이 쓴 글을 근거로 인용: config-example.yaml |
| 중 4 | google.golang.org/grpc | v1.69.0 | GO-2026-6061 |  | 0.000 | 1.82.1 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | github.com/go-viper/mapstructure/v2 | v2.2.1 | GO-2025-3787 |  | 0.000 | 2.3.0 | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | github.com/docker/docker | v27.4.0+incompatible | CVE-2026-34040 |  | 0.093 |  | 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌 |
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2026-39821 |  | 0.018 | 0.55.0 | 에이전트가 근거 부족으로 판단을 보류함 |

### google.golang.org/grpc CVE-2026-33186

- 회차별 판단: mitigating_control_protected, mitigating_control_protected
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): google.golang.org/grpc.*Server.Serve < github.com/juanfont/headscale/hscontrol.Serve$1 < golang.org/x/sync/errgroup.Go$1 < golang.org/x/sync/errgroup.*Group.Go < github.com/juanfont/headscale/integration.*Scenario.WaitForTailscaleLogout
- 에이전트 설명: google.golang.org/grpc v1.69.0 is declared in go.mod. That is below the fixed version 1.79.3, so the version is affected. The repo runs grpc.Server instances, so the server path handling is reachable. The advisory's exploit needs path-based authorization, either grpc/authz or interceptors that read info.FullMethod or grpc.Method(ctx), with deny rules for canonical paths and a default-allow fallback. This repo has no such authorization. The remote gRPC server has one chained unary interceptor, gr
- 인용: go.mod:46 google.golang.org/grpc v1.69.0
- 인용: hscontrol/app.go:740 grpcServer = grpc.NewServer(grpcOptions...)
- 인용: hscontrol/app.go:725 h.grpcAuthenticationInterceptor,
- 인용: hscontrol/app.go:319 func (h *Headscale) grpcAuthenticationInterceptor(ctx context.Context,

### golang.org/x/oauth2 CVE-2025-22868

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 근거 재현 검사 실패: 범위를 읽지 못해 저장소 전체로 다시 찾으니 3건: google\.golang\.org/api|cloud\.google\.com|oauth2/(jwt|googl @ **/*.go and go.mod
- 에이전트 설명: CVE-2025-22868 (GO-2025-3488) affects golang.org/x/oauth2 before v0.27.0. The vulnerable function is jws.Verify in the golang.org/x/oauth2/jws subpackage. This repo resolves golang.org/x/oauth2 to v0.24.0, which is inside the affected range, so the module is present and affected. First-party code uses only the root oauth2 package, in hscontrol/oidc.go: oauth2.Config, AuthCodeOption, GenerateVerifier, S256ChallengeOption, SetAuthURLParam, VerifierOption and AccessTypeOffline. No Go file in the re
- 인용: go.mod:43 golang.org/x/oauth2 v0.24.0
- 인용: hscontrol/oidc.go:23 "golang.org/x/oauth2"
- 인용: hscontrol/oidc.go:65 oauth2Config *oauth2.Config

### github.com/golang-jwt/jwt/v5 CVE-2025-30204

- 회차별 판단: uncertain, requires_configuration
- 사유: 에이전트가 근거 부족으로 판단을 보류함
- 에이전트 설명: Presence is confirmed. go.mod pins github.com/golang-jwt/jwt/v5 v5.2.1 as an indirect dependency, which is inside the affected range >=5.0.0-rc.1 <5.2.2 (fixed in 5.2.2). No first-party Go file imports golang-jwt directly. The only importer I could find is github.com/oauth2-proxy/mockoidc, whose go.mod requires jwt/v5. I read that go.mod through a web fetch, not from a local file, and it is not in the repo. Headscale compiles mockoidc into its binary through cmd/headscale/cli/mockoidc.go, which 
- 인용: go.mod:131 github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
- 인용: go.mod:22 github.com/oauth2-proxy/mockoidc v0.0.0-20240214162133-caebfff84d25
- 인용: cmd/headscale/cli/mockoidc.go:12 "github.com/oauth2-proxy/mockoidc"
- 인용: cmd/headscale/cli/mockoidc.go:99 err = mock.Start(listener, nil)

### github.com/opencontainers/runc CVE-2025-52565

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 저장소 글 차단: 사람이 쓴 글을 근거로 인용: integration/dockertestutil/config.go
- 에이전트 설명: CVE-2025-52565 (GHSA-qw9x-cqr3-wc7r) affects github.com/opencontainers/runc 1.0.0-rc3 to 1.2.7, 1.3.0-rc.1 to 1.3.2 and 1.4.0-rc.1 to 1.4.0-rc.2. The fixes are in 1.2.8, 1.3.3 and 1.4.0-rc.3. The flaw is in the container runtime's setup of the /dev/pts/$n to /dev/console bind mount when it starts a container. go.mod pins runc v1.2.3 as an indirect dependency, so the version is in the affected range. The vulnerable code runs inside the runc binary (libcontainer init) when a container is created. 
- 인용: go.mod:181 github.com/opencontainers/runc v1.2.3 // indirect
- 인용: integration/dockertestutil/config.go:36 // https://github.com/opencontainers/runc/commit/2ce40b6ad72b4bd4391380cafc5ef1bad1fa0b31

### github.com/opencontainers/runc CVE-2025-52881

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): github.com/opencontainers/runc/libcontainer/user.CurrentUser < github.com/ory/dockertest/v3/docker/pkg/homedir.Get < github.com/ory/dockertest/v3/docker.getDockerEnv < github.com/ory/dockertest/v3/docker.NewVersionedClientFromEnv < github.com/ory/dockertest/v3/docker.NewClientFromEnv < github.com/ory/dockertest/v3.NewPool < github.com/juanfont/headscale/integration.NewScenario
- 에이전트 설명: The advisory (GHSA-cgrx-mc8f-2prm) covers github.com/opencontainers/runc <=1.2.7, 1.3.0-rc.1 to 1.3.2, and 1.4.0-rc.1 to 1.4.0-rc.2. The fixes are 1.2.8, 1.3.3 and 1.4.0-rc.3. go.mod and go.sum resolve runc to v1.2.3, so the version is in the affected range. The entry is an indirect dependency only. It most likely comes in through github.com/ory/dockertest and docker/docker, but I did not run `go mod why` to confirm that. No Go file in the repository imports runc or libcontainer, and there is no
- 인용: go.mod:181 github.com/opencontainers/runc v1.2.3 // indirect
- 인용: go.sum:368 github.com/opencontainers/runc v1.2.3 h1:fxE7amCzfZflJO2lHXf4y/y8M1BoAqp+FVmG19oYB80=
- 인용: go.mod:23 github.com/ory/dockertest/v3 v3.11.0
- 인용: integration/dockertestutil/config.go:6 "github.com/ory/dockertest/v3/docker"

### github.com/go-jose/go-jose/v3 CVE-2026-34986

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): github.com/go-jose/go-jose/v3.init < github.com/oauth2-proxy/mockoidc.init < github.com/juanfont/headscale/cmd/headscale/cli.init
- 에이전트 설명: The advisory (GHSA-78h2-9frx-2jm8 / GO-2026-4945) covers a panic in go-jose JWE decryption. cipher.KeyUnwrap() panics when a JWE uses a key-wrapping alg (*KW, excluding AxxxGCMKW) and has an empty encrypted_key. It is reached through ParseEncrypted*/Decrypt. Affected ranges are v3 3.0.0-3.0.4 (fixed 3.0.5) and v4 4.0.0-4.1.3 (fixed 4.1.4). This repo resolves go-jose/v3 v3.0.3 and go-jose/v4 v4.0.2, both in the affected ranges, but only as indirect dependencies. No first-party Go file imports go-
- 인용: go.mod:124 github.com/go-jose/go-jose/v3 v3.0.3 // indirect
- 인용: go.mod:125 github.com/go-jose/go-jose/v4 v4.0.2 // indirect
- 인용: go.mod:10 github.com/coreos/go-oidc/v3 v3.11.0
- 인용: hscontrol/oidc.go:15 "github.com/coreos/go-oidc/v3/oidc"

### github.com/go-jose/go-jose/v4 CVE-2026-34986

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): github.com/go-jose/go-jose/v4.ParseSigned < github.com/coreos/go-oidc/v3/oidc.*IDTokenVerifier.Verify < github.com/juanfont/headscale/hscontrol.*AuthProviderOIDC.extractIDToken < github.com/juanfont/headscale/hscontrol.*AuthProviderOIDC.OIDCCallbackHandler
- 에이전트 설명: go-jose is present only as an indirect dependency, at v3.0.3 and v4.0.2. Both are inside the affected ranges (v3 3.0.0-3.0.4, v4 4.0.0-4.1.3). The flaw is a panic in cipher.KeyUnwrap, reached through ParseEncrypted/ParseEncryptedJSON/ParseEncryptedCompact followed by Decrypt on a JWE. No first-party Go file imports go-jose or calls any JWE API. The only route to go-jose is github.com/coreos/go-oidc/v3 v3.11.0, called from hscontrol/oidc.go. Its IDTokenVerifier.Verify and RemoteKeySet only use jo
- 인용: go.mod:125 github.com/go-jose/go-jose/v4 v4.0.2 // indirect
- 인용: go.mod:124 github.com/go-jose/go-jose/v3 v3.0.3 // indirect
- 인용: go.mod:10 github.com/coreos/go-oidc/v3 v3.11.0
- 인용: hscontrol/oidc.go:15 "github.com/coreos/go-oidc/v3/oidc"

### google.golang.org/grpc CVE-2026-84445

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): google.golang.org/grpc/internal/transport.*http2Server.HandleStreams < google.golang.org/grpc.*Server.serveStreams < google.golang.org/grpc.handleRawConn$1 < google.golang.org/grpc.*Server.handleRawConn < google.golang.org/grpc.Serve$3 < google.golang.org/grpc.*Server.Serve < github.com/juanfont/headscale/hscontrol.Serve$1 < golang.org/x/sync/errgroup.Go$1
- 에이전트 설명: The advisory (GO-2026-6443 / GHSA-2v4p-qf9q-27wj, alias CVE-2026-84445) affects google.golang.org/grpc before 1.82.2 and 1.83.0 up to 1.83.2. The panic is in the xDS routing code, `RouteAndProcess` in `internal/xds/server`, and only affects servers built with `xds.NewGRPCServer()`. This repository resolves grpc v1.69.0, which is in the affected range, so the package is present. The repository's only gRPC servers are plain `grpc.NewServer(...)`, one on a local unix socket and one remote (TLS or i
- 인용: go.mod:46 google.golang.org/grpc v1.69.0
- 인용: hscontrol/app.go:685 grpcSocket := grpc.NewServer(
- 인용: hscontrol/app.go:740 grpcServer = grpc.NewServer(grpcOptions...)

### google.golang.org/grpc CVE-2026-84304

- 회차별 판단: requires_configuration, requires_configuration
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): google.golang.org/grpc/mem.ReadAll < google.golang.org/grpc.decompress < google.golang.org/grpc.recvAndDecompress < google.golang.org/grpc.recv < google.golang.org/grpc.*csAttempt.recvMsg < google.golang.org/grpc.RecvMsg$1 < google.golang.org/grpc.*clientStream.withRetry < google.golang.org/grpc.*clientStream.SendMsg
- 에이전트 설명: CVE-2026-84304 (GHSA-vp52-pcj8-j9qc, GO-2026-6348) is an unauthenticated heap exhaustion in grpc-go. Fragmented HTTP/2 DATA frames are each stored as a separate recvMsg in internal/transport recvBuffer. It affects versions before 1.83.1. This repo resolves google.golang.org/grpc v1.69.0, which is in the affected range, and hscontrol/app.go creates two grpc.Server instances. The network-reachable one (app.go:740) is created only when `tlsConfig != nil || GRPCAllowInsecure`. By default tls_letsenc
- 인용: go.mod:46 google.golang.org/grpc v1.69.0
- 인용: go.sum:688 google.golang.org/grpc v1.69.0 h1:quSiOM1GJPmPH5XtU+BCoVXcDVJJAzNcoyfC2cCjGkI=
- 인용: hscontrol/app.go:685 grpcSocket := grpc.NewServer(
- 인용: hscontrol/app.go:719 if tlsConfig != nil || h.cfg.GRPCAllowInsecure {

### github.com/go-jose/go-jose/v3 CVE-2026-116587

- 회차별 판단: requires_configuration, requires_configuration
- 사유: 저장소 글 차단: 사람이 쓴 글을 근거로 인용: config-example.yaml
- 에이전트 설명: CVE-2026-116587 (GHSA-mgcc-cww5-fp2q) affects github.com/go-jose/go-jose v3 <= 3.0.5 and v4 <= 4.1.5. The fix is v4.1.6, and v3 has no fix. A crafted RSA JWK makes crypto/rsa.PrivateKey.Validate burn cubic CPU on Go 1.24+. The repo resolves go-jose v3.0.3 and v4.0.2, both in range, as indirect dependencies only. No first-party Go file imports go-jose or calls jose APIs. The only route in is transitive: hscontrol/oidc.go calls verifier.Verify(), and go-oidc v3.11.0 then calls jose.ParseSigned (fr
- 인용: go.mod:125 github.com/go-jose/go-jose/v4 v4.0.2 // indirect
- 인용: go.mod:124 github.com/go-jose/go-jose/v3 v3.0.3 // indirect
- 인용: go.mod:10 github.com/coreos/go-oidc/v3 v3.11.0
- 인용: hscontrol/oidc.go:367 idToken, err := verifier.Verify(ctx, rawIDToken)

### github.com/go-jose/go-jose/v4 CVE-2026-116587

- 회차별 판단: requires_environment, requires_configuration
- 사유: 저장소 글 차단: 사람이 쓴 글을 근거로 인용: config-example.yaml
- 에이전트 설명: Advisory GHSA-mgcc-cww5-fp2q (CVE-2026-116587) covers github.com/go-jose/go-jose v4 <= 4.1.5 and v3 <= 3.0.5. Parsing a JWK with attacker-chosen RSA modulus and prime values calls crypto/rsa.PrivateKey.Validate, which takes cubic CPU time on Go 1.24 and later. The advisory's PoC is jose.ParseSigned with an embedded JWK in the protected header.
This repo resolves go-jose v3.0.3 and v4.0.2 as indirect dependencies, both in the affected range, so the package is present. They come in through github.
- 인용: go.mod:125 github.com/go-jose/go-jose/v4 v4.0.2 // indirect
- 인용: go.mod:124 github.com/go-jose/go-jose/v3 v3.0.3 // indirect
- 인용: go.mod:10 github.com/coreos/go-oidc/v3 v3.11.0
- 인용: hscontrol/oidc.go:367 idToken, err := verifier.Verify(ctx, rawIDToken)

### google.golang.org/grpc GO-2026-6061

- 회차별 판단: requires_configuration, requires_configuration
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): google.golang.org/grpc/internal/transport.*ServerStream.Read < google.golang.org/grpc.*parser.recvMsg < google.golang.org/grpc.recvAndDecompress < google.golang.org/grpc.recv < google.golang.org/grpc.*csAttempt.recvMsg < google.golang.org/grpc.RecvMsg$1 < google.golang.org/grpc.*clientStream.withRetry < google.golang.org/grpc.*clientStream.SendMsg
- 에이전트 설명: google.golang.org/grpc v1.69.0 is resolved, which is before the fixed v1.82.1, so it is in the affected range. The advisory covers three issues. Two are in the xDS RBAC engine: an authorization fail-open and a panic. The third is a bypass of the HTTP/2 Rapid Reset mitigation in internal/transport, which allows a remote DoS. The repository never imports google.golang.org/grpc/xds or the RBAC engine, so the two RBAC issues are not reachable. The transport issue is reachable only through grpc.NewSe
- 인용: go.mod:46 google.golang.org/grpc v1.69.0
- 인용: hscontrol/app.go:719 if tlsConfig != nil || h.cfg.GRPCAllowInsecure {
- 인용: hscontrol/app.go:740 grpcServer = grpc.NewServer(grpcOptions...)
- 인용: hscontrol/app.go:750 errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

### github.com/go-viper/mapstructure/v2 GO-2025-3787

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): github.com/go-viper/mapstructure/v2/internal/errors.init < github.com/go-viper/mapstructure/v2.init < github.com/spf13/viper.init < github.com/juanfont/headscale/hscontrol/util.init
- 에이전트 설명: GO-2025-3787 (GHSA-fv92-fjc5-jj9h, no CVE) affects github.com/go-viper/mapstructure/v2 before v2.3.0. When a decode fails (WeakDecode and the decode helpers behind it), the error text includes the raw input value, which can leak sensitive data into logs or responses. This repo resolves the module to v2.2.1 as an indirect dependency of spf13/viper v1.20.0-alpha.6, so the version is in range. The only decode path is viper.UnmarshalKey("dns.extra_records", &extraRecords) in hscontrol/types/config.g
- 인용: go.mod:128 github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
- 인용: go.mod:34 github.com/spf13/viper v1.20.0-alpha.6
- 인용: hscontrol/types/config.go:644 err := viper.UnmarshalKey("dns.extra_records", &extraRecords)
- 인용: hscontrol/types/config.go:646 return DNSConfig{}, fmt.Errorf("unmarshalling dns extra records: %w", err)

### github.com/docker/docker CVE-2026-34040

- 회차별 판단: code_not_reachable, code_not_reachable
- 사유: 호출 그래프가 취약 함수 호출을 찾아 에이전트의 닫기 판단과 충돌
- 호출 경로(취약 함수에서 진입점으로): github.com/docker/docker/api/types/swarm.init < github.com/docker/cli/opts.init < github.com/docker/cli/cli/compose/loader.init < github.com/ory/dockertest/v3/docker/opts.init < github.com/ory/dockertest/v3/docker.init < github.com/juanfont/headscale/integration/tsic.init
- 에이전트 설명: The advisory (GHSA-x744-4wpc-v9h2, CVE-2026-34040) covers the Docker Engine daemon module github.com/moby/moby, published in Go as github.com/docker/docker. Affected versions are below 29.3.1. The flaw is in the daemon, which can forward a crafted oversized API request to an AuthZ plugin without the request body. The advisory says that if you don't use AuthZ plugins, you are not affected. This repo resolves github.com/docker/docker v27.4.0+incompatible, which is inside the affected range. It is 
- 인용: go.mod:116 github.com/docker/docker v27.4.0+incompatible // indirect
- 인용: go.mod:23 github.com/ory/dockertest/v3 v3.11.0
- 인용: integration/dockertestutil/logs.go:11 "github.com/ory/dockertest/v3"

### golang.org/x/net CVE-2026-39821

- 회차별 판단: uncertain, uncertain
- 사유: 에이전트가 근거 부족으로 판단을 보류함
- 에이전트 설명: The affected package is present, but I could not establish that the flaw is reachable from an attacker-controlled input. CVE-2026-39821 (GO-2026-5026) affects golang.org/x/net/idna (ToASCII, ToUnicode) before 0.55.0, and the Go stdlib net/http (idnaASCII) before 1.25.13 and 1.26.6. go.mod pins golang.org/x/net v0.32.0, which is in the affected range, and the go directive is 1.23.1.\n\nNo first-party code imports or calls x/net/idna directly (0 hits). The only first-party x/net use is http2.Serve
- 인용: go.mod:42 golang.org/x/net v0.32.0
- 인용: go.mod:3 go 1.23.1
- 인용: hscontrol/noise.go:107 noiseServer.http2Server = &http2.Server{}
- 인용: hscontrol/derp/derp.go:46 resp, err := client.Do(req)

## 근거와 함께 닫음

| 영향도 | 패키지 | 버전 | CVE | KEV | EPSS | 수정 버전 | 이유 |
|---|---|---|---|---|---:|---|---|
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-42508 |  | 0.069 | 0.52.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39830 |  | 0.007 | 0.52.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39832 |  | 0.007 | 0.52.0 | code_not_reachable |
| 중 4 | github.com/jackc/pgx/v5 | v5.7.1 | CVE-2026-33815 |  | 0.006 | 5.9.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39834 |  | 0.006 | 0.52.0 | code_not_reachable |
| 중 4 | github.com/jackc/pgx/v5 | v5.7.1 | CVE-2026-33816 |  | 0.006 | 5.9.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-46595 |  | 0.006 | 0.52.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39831 |  | 0.005 | 0.52.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39833 |  | 0.005 | 0.52.0 | code_not_reachable |
| 중 4 | github.com/opencontainers/runc | v1.2.3 | CVE-2025-31133 |  | 0.012 | 1.2.8, 1.3.3 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2025-22869 |  | 0.009 | 0.35.0 | code_not_reachable |
| 중 4 | github.com/klauspost/compress | v1.17.11 | CVE-2026-63209 |  | 0.006 | 1.18.7 | code_not_reachable |
| 중 4 | github.com/docker/cli | v27.4.0+incompatible | CVE-2025-15558 |  | 0.005 | 29.2.0, 29.2.0+incompatible | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-46597 |  | 0.005 | 0.52.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2026-39829 |  | 0.005 | 0.52.0 | code_not_reachable |
| 중 4 | github.com/docker/docker | v27.4.0+incompatible | CVE-2026-41567 |  | 0.002 |  | code_not_reachable |
| 중 4 | github.com/docker/docker | v27.4.0+incompatible | CVE-2026-42306 |  | 0.001 |  | code_not_reachable |
| 중 4 | github.com/insomniacslk/dhcp | v0.0.0-20240129002554-15c9b8791914 | GO-2026-6237 |  | 0.000 | 0.0.0-20260719225207-c76316d4aa82 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | GO-2026-5932 |  | 0.000 |  | code_not_reachable |
| 중 4 | golang.org/x/net | v0.32.0 | CVE-2024-45338 |  | 0.011 | 0.33.0 | code_not_reachable |
| 중 4 | golang.org/x/crypto | v0.31.0 | CVE-2025-47913 |  | 0.007 | 0.43.0 | code_not_reachable |

## 조치안 검증

복사본에서 패키지별로 버전을 올려 빌드와 시험을 돌렸다. 코드 반영과 배포는 담당자가 한다.

| 패키지 | 올린 버전 | 대상 CVE | 결과 |
|---|---|---|---|
| golang.org/x/net | v0.32.0 > v0.60.0 | CVE-2026-33814, CVE-2026-78659, CVE-2026-78663, CVE-2026-78669, CVE-2026-39821 | 반영 |
| google.golang.org/grpc | v1.69.0 > v1.83.2 | CVE-2026-33186, CVE-2026-84445, CVE-2026-84304, GO-2026-6061 | 반영 |
| golang.org/x/oauth2 | v0.24.0 > v0.36.0(요청 v0.27.0, 다른 패키지를 올리며 함께 오름) | CVE-2025-22868 | 반영 |
| github.com/golang-jwt/jwt/v5 | v5.2.1 > v5.2.2 | CVE-2025-30204 | 반영 |
| github.com/opencontainers/runc | v1.2.3 > v1.3.3 | CVE-2025-52565, CVE-2025-52881 | 반영 |
| github.com/go-jose/go-jose/v3 | v3.0.3 > v3.0.5 | CVE-2026-34986 | 반영 |
| github.com/go-jose/go-jose/v4 | v4.0.2 > v4.1.6 | CVE-2026-34986, CVE-2026-116587 | 반영 |
| github.com/go-viper/mapstructure/v2 | v2.2.1 > v2.3.0 | GO-2025-3787 | 반영 |

- 시험: 고치기 전 통과 패키지 10, 실패 시험 0. 고친 뒤 통과 패키지 10, 실패 시험 0. 새 실패 0건.
- 재스캔: 경보 133건에서 38건. 대상 취약점 16건 중 남은 것 1건. 새로 생긴 경보 ID 0건.
- 담당자 확인: Go 언어 버전이 1.23.1에서 1.26.0로 올라간다. CI와 컨테이너 이미지를 함께 올려야 한다.
- 담당자 확인: 함께 바뀌는 다른 의존성 12개(직접 5, 간접 7): github.com/containerd/console v1.0.4 > v1.0.5, github.com/google/go-cmp v0.6.0 > v0.7.0, golang.org/x/crypto v0.31.0 > v0.57.0, golang.org/x/mod v0.22.0 > v0.41.0, golang.org/x/sync v0.10.0 > v0.23.0, golang.org/x/sys v0.28.0 > v0.48.0, golang.org/x/term v0.27.0 > v0.46.0, golang.org/x/text v0.21.0 > v0.42.0, golang.org/x/tools v0.28.0 > v0.49.0, google.golang.org/genproto/googleapis/api v0.0.0-20241216192217-9240e9c98484 > v0.0.0-20260526163538-3dc84a4a5aaa, google.golang.org/genproto/googleapis/rpc v0.0.0-20241216192217-9240e9c98484 > v0.0.0-20260526163538-3dc84a4a5aaa, google.golang.org/protobuf v1.36.0 > v1.36.11
