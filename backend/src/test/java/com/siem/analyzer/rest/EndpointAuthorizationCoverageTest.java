package com.siem.analyzer.rest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.security.Authenticated;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Path;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class EndpointAuthorizationCoverageTest {

    private static final java.nio.file.Path COMPILED_CLASSES =
            java.nio.file.Path.of("target", "classes", "com", "siem", "analyzer");

    private static final List<Class<? extends Annotation>> AUTHORIZATION_ANNOTATIONS =
            List.of(RolesAllowed.class, PermitAll.class, DenyAll.class, Authenticated.class);

    @Test
    void everyEndpointCarriesAnAuthorizationAnnotation() {
        List<Class<?>> resources = resourceClasses();

        assertFalse(resources.isEmpty(), "no @Path classes found under " + COMPILED_CLASSES);

        List<String> unguarded = new ArrayList<>();
        for (Class<?> resource : resources) {
            for (Method method : resource.getDeclaredMethods()) {
                if (isEndpoint(method) && !isGuarded(method)) {
                    unguarded.add(resource.getSimpleName() + "." + method.getName());
                }
            }
        }

        assertTrue(
                unguarded.isEmpty(),
                "endpoints with no @RolesAllowed, @PermitAll, @DenyAll or @Authenticated on the"
                        + " method or its class: "
                        + unguarded);
    }

    private static List<Class<?>> resourceClasses() {
        assertTrue(
                Files.isDirectory(COMPILED_CLASSES),
                COMPILED_CLASSES + " is missing; the main sources must be compiled first");

        try (Stream<java.nio.file.Path> tree = Files.walk(COMPILED_CLASSES)) {
            return tree.filter(file -> file.toString().endsWith(".class"))
                    .map(EndpointAuthorizationCoverageTest::load)
                    .filter(type -> type.isAnnotationPresent(Path.class))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("could not walk " + COMPILED_CLASSES, e);
        }
    }

    private static Class<?> load(java.nio.file.Path classFile) {
        String relative =
                java.nio.file.Path.of("target", "classes").relativize(classFile).toString();
        String className =
                relative.substring(0, relative.length() - ".class".length())
                        .replace(java.io.File.separatorChar, '.');
        try {

            return Class.forName(
                    className, false, EndpointAuthorizationCoverageTest.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("compiled class " + className + " will not load", e);
        }
    }

    private static boolean isEndpoint(Method method) {
        return Stream.of(method.getAnnotations())
                .anyMatch(a -> a.annotationType().isAnnotationPresent(HttpMethod.class));
    }

    private static boolean isGuarded(Method method) {
        return AUTHORIZATION_ANNOTATIONS.stream()
                .anyMatch(
                        annotation ->
                                method.isAnnotationPresent(annotation)
                                        || method.getDeclaringClass()
                                                .isAnnotationPresent(annotation));
    }
}
