add code 

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.1.2'
    }
}


plugins {
    id 'java'
    id 'org.owasp.dependencycheck' version '6.2.2'
}
apply plugin: 'org.owasp.dependencycheck'

group 'org.example'
version '1.0-SNAPSHOT'

repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}
dependencyCheck {
    formats = ['HTML', 'XML','json']
    outputDirectory = file('build/jafar-report')


}
