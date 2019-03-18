FROM node
LABEL maintainer="estafette.io" \
      description="The estafette-extension-npm-audit component is an Estafette extension to send build status updates to Slack for vulnerabilities in npm packages."

COPY estafette-extension-npm-audit /

ENTRYPOINT ["/estafette-extension-npm-audit"]
