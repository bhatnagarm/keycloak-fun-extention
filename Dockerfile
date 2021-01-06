FROM jboss/keycloak:12.0.1

COPY themes/target/classes/ /opt/jboss/keycloak/
RUN sh /opt/jboss/keycloak/bin/add-user.sh -u test -p changeit

ENV KEYCLOAK_USER admin
ENV KEYCLOAK_PASSWORD admin
ENV KEYCLOAK_DEFAULT_THEME custom

ENV KEYCLOAK_LOGLEVEL INFO
ENV ROOT_LOGLEVEL ERROR