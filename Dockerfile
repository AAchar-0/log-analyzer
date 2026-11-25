# Multi-stage build: stage 1 compiles and packages, stage 2 is a small image that only runs the app.
# Same pattern as the inventory-api project.

# ---- Stage 1: build ----
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

# ---- Stage 2: run ----
FROM eclipse-temurin:21-jre
RUN useradd --system --create-home appuser
USER appuser
WORKDIR /app
COPY --from=build /build/target/log-analyzer.jar app.jar
EXPOSE 8080
# MaxRAMPercentage lets Java use most of the memory the host gives it (the free tier has 512 MB).
# The hosting platform sets PORT; the app reads it. "serve" starts the web app.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "app.jar"]
CMD ["serve"]
