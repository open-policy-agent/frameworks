module github.com/open-policy-agent/frameworks/constraint

go 1.16

// Downgrade logr until we upgrade apimachinery.
replace github.com/go-logr/logr => github.com/go-logr/logr v0.4.0

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/golang/glog v1.0.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/open-policy-agent/opa v0.37.2
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/spf13/cobra v1.3.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	k8s.io/apiextensions-apiserver v0.21.2
	k8s.io/apimachinery v0.22.6
	k8s.io/client-go v0.22.6
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.9.2
	sigs.k8s.io/yaml v1.3.0
)
