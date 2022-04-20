# Build the manager binary
FROM golang:1.18 as builder

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
ENV version=3.8.9
ENV arch=amd64
ENV tar_name=kustomize_v${version}_linux_${arch}.tar.gz
RUN curl -LO "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${version}/${tar_name}" &&\
    tar -xf ${tar_name} &&\
    mv ./kustomize /usr/bin/kustomize &&\
    chmod u+x /usr/bin/kustomize

# Copy in the go src
WORKDIR /go/src/github.com/open-policy-agent/frameworks/constraint
COPY .    .

ENTRYPOINT ["make", "docker-internal-test"]
