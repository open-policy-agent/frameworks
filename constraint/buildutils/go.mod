module github.com/open-policy-agent/frameworks/constraint

go 1.13

require (
	sigs.k8s.io/controller-runtime v0.1.9
	k8s.io/client-go kubernetes-1.12.3
	k8s.io/api kubernetes-1.12.3
	k8s.io/apimachinery kubernetes-1.12.3
	k8s.io/apiextensions-apiserver kubernetes-1.12.3
)

replace (
	k8s.io/client-go => k8s.io/client-go v0.0.0-20181126152608-d082d5923d3c
	k8s.io/api => k8s.io/api v0.0.0-20181126151915-b503174bad59
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20181126123746-eddba98df674
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20181126155829-0cd23ebeb688
)