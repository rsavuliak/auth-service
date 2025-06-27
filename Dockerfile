FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY target/auth-service.jar app.jar
#ENV JAVA_TOOL_OPTIONS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
ENTRYPOINT ["java", "-jar", "app.jar"]