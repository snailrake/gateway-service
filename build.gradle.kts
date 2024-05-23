plugins {
    java
    id("org.springframework.boot") version "3.2.5"
    id("io.spring.dependency-management") version "1.1.4"
}

group = "ru.intership"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    /**
     * Spring cloud starters
     */
    implementation("org.springframework.cloud:spring-cloud-starter-gateway:4.1.3")
    implementation("org.springframework.cloud:spring-cloud-starter-netflix-eureka-client:4.1.1")

    /**
     * Security
     */
    implementation("org.springframework.boot:spring-boot-starter-security:3.2.5")
    implementation("org.springframework.security:spring-security-oauth2-resource-server:6.3.0")
    implementation("org.springframework.security:spring-security-oauth2-jose:6.3.0")

    /**
     * Keycloak
     */
    implementation("org.keycloak:keycloak-admin-client:24.0.4")

    /**
     * Tests
     */
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    /**
     * Utils
     */
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
