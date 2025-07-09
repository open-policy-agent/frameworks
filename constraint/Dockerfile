FROM golang:1.24-bookworm@sha256:69adc37c19ac6ef724b561b0dc675b27d8c719dfe848db7dd1092a7c9ac24bc6 as builder

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
