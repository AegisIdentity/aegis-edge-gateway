# syntax=docker/dockerfile:1
# Runtime image. Build the fat jar first (mvn -q -DskipTests package) — the polyrepo shares the
# aegis-platform-parent/commons artifacts via ~/.m2, so the compose 'build' step copies the
# pre-built jar rather than rebuilding the reactor inside the image. Minimal JRE, non-root.
FROM eclipse-temurin:21-jre AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN groupadd --system aegis && useradd --system --gid aegis --home /app aegis
COPY target/*.jar /app/app.jar
USER aegis
EXPOSE 8080
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=12 \
    CMD curl -fsS http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar /app/app.jar"]
