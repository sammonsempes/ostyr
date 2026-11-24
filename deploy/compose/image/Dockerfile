FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
COPY --chown=65532:65532 ostyr-platform ostyr-auth ostyr-web-ui ostyr-playbooks /usr/local/bin/
COPY --chown=65532:65532 state/ /var/lib/ostyr/
COPY --chown=65533:65533 playbooks-state/ /var/lib/ostyr-playbooks/
USER 65532:65532
EXPOSE 8443 9443
CMD ["/usr/local/bin/ostyr-platform", "/etc/ostyr/module.yaml"]
