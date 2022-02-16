module github.com/open-policy-agent/frameworks/constraint

go 1.16

replace go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.20.0

replace go.opentelemetry.io/otel => go.opentelemetry.io/otel v0.20.0

replace go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp => go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0

replace go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v0.20.0

replace go.opentelemetry.io/otel/trace => go.opentelemetry.io/otel/trace v0.20.0

replace go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.7.0

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/golang/glog v1.0.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/kr/pty v1.1.5 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/open-policy-agent/opa v0.37.2
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/spf13/cobra v1.3.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/objx v0.2.0 // indirect
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200910180754-dd1b699fc489 // indirect
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	k8s.io/apiextensions-apiserver v0.23.0
	k8s.io/apimachinery v0.23.0
	k8s.io/client-go v0.23.0
	k8s.io/klog/v2 v2.40.1 // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/utils v0.0.0-20210930125809-cb0fa318a74b
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.27 // indirect
	sigs.k8s.io/controller-runtime v0.11.1
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0
)
