FROM golang:1.24-bookworm@sha256:7b25b1ea217e0a56060953b3d4859134ecbe757d7434f7ce4756e0c25aad1ef0 as builder

ARG KUSTOMIZE_VERSION

ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y make

# Install kustomize
RUN curl -L -O "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz" &&\
    tar -zxvf kustomize_v${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz &&\
    chmod +x kustomize &&\
    mv kustomize /usr/local/bin

WORKDIR /app
