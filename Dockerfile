FROM jboss/keycloak:12.0.1

USER root
MAINTAINER mitul bhatnagar

COPY themes/target/classes/ /opt/jboss/keycloak/
COPY themes/src/main/example-realm.json /opt/jboss/keycloak/example-realm.json

ENV UNIQUE_NODE_ID="1" \
    KEYCLOAK_USER=admin \
    KEYCLOAK_PASSWORD=admin \
    KEYCLOAK_DEFAULT_THEME=custom \
    KEYCLOAK_LOGLEVEL=INFO \
    ROOT_LOGLEVEL=ERROR \
    KEYCLOAK_USER=admin \
    KEYCLOAK_PASSWORD=admin
#    DB_VENDOR=POSTGRES \
#    DB_ADDR="localhost" \
#    DB_PORT=5432 \
#    DB_DATABASE=postgres \
#    DB_USER=postgres \
#    DB_PASSWORD=postgres \
#    DB_SCHEMA=keycloak_service

# Add a jboss admin user so we can access the management console - ignore errors if user already existed by always returning code 0.
RUN /opt/jboss/keycloak/bin/add-user.sh admin admin --silent; exit 0;



# The following ports are exposed:
#
# 8400 - Remote Java debugging port
# 9990 - The Web Management Console port e.g. http://127.0.0.1:9990/console/index.html
# 8443 - HTTPS endpoint for Keycloak APIs and Console e.g. https://127.0.0.1:8443/auth/
# 7600 - Unicast peer discovery in HA clusters using TCP i.e. JBoss JGroups TCPPING port
# 57600 - Used for HA failure detection over TCP.
# 45700 - Multicast port. Used to discover initial membership in a HA cluster.
#
# See https://access.redhat.com/documentation/en-us/jboss_enterprise_application_platform/6/html/installation_guide/network_ports_used_by_jboss_enterprise_application_platform_62
EXPOSE 8443 8400 9990 7600 57600 45700