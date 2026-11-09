FROM gcr.io/distroless/cc-debian13:nonroot
COPY --chown=65532:65532 ostyr-example-module /usr/local/bin/ostyr-example-module
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/ostyr-example-module"]
CMD ["/etc/ostyr/module.yaml"]
