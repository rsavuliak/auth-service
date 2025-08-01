FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY target/auth-service.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]