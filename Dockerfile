FROM python:3.12-slim

WORKDIR /opt/siteadmin
COPY pyproject.toml ./
RUN pip install --no-cache-dir "cryptography>=42,<46"
COPY siteadmin ./siteadmin

ENV SITEADMIN_STATE_DIR=/var/lib/siteadmin
ENV SITEADMIN_INSTALL_DIR=/opt/siteadmin
VOLUME ["/var/lib/siteadmin", "/var/lib/serverctl"]

ENTRYPOINT ["python", "-m", "siteadmin"]
CMD ["run"]
