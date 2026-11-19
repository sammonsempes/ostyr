FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
COPY --chown=65532:65532 platform_api auth_tool /usr/local/bin/
COPY --chown=65532:65532 state/ /var/lib/ostyr/
USER 65532:65532
EXPOSE 8443
CMD ["/usr/local/bin/platform_api", "/etc/ostyr/module.yaml"]
