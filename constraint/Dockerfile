# Build the manager binary
FROM golang:1.15 as builder

RUN apt-get update &&\
    apt-get install -y apt-utils make

# Install kubebuilder
WORKDIR /scratch
ENV version=2.3.2
ENV arch=amd64
RUN curl -L -O "https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${version}/kubebuilder_${version}_linux_${arch}.tar.gz" &&\
    tar -zxvf kubebuilder_${version}_linux_${arch}.tar.gz &&\
    mv kubebuilder_${version}_linux_${arch} /usr/local/kubebuilder &&\
    rm kubebuilder_${version}_linux_${arch}.tar.gz
ENV PATH=$PATH:/usr/local/kubebuilder/bin:/usr/bin

# Install kustomize
ENV version=3.0.2
ENV arch=amd64
RUN curl -L -O "https://github.com/kubernetes-sigs/kustomize/releases/download/v${version}/kustomize_${version}_linux_${arch}" &&\
    mv kustomize_${version}_linux_${arch} /usr/bin/kustomize &&\
    chmod u+x /usr/bin/kustomize

# Install OPA
WORKDIR /usr/bin
RUN curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.10.5/opa_linux_amd64 &&\
    chmod 755 opa

# Copy in the go src
WORKDIR /go/src/github.com/open-policy-agent/frameworks/constraint
COPY .    .

ENV GO111MODULE=off

ENTRYPOINT ["make", "docker-internal-test"]
