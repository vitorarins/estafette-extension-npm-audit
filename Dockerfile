FROM node:13.6.0-alpine
LABEL maintainer="estafette.io" \
      description="The estafette-extension-npm-audit component is an Estafette extension to send build status updates to Slack for vulnerabilities in npm packages."

COPY ca-certificates.crt /etc/ssl/certs/
COPY estafette-extension-npm-audit /

ENV ESTAFETTE_LOG_FORMAT="console"

ENTRYPOINT ["/estafette-extension-npm-audit"]